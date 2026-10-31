package Maat::Spool;

use 5.010;
use strict;
use warnings;
use File::Path ();
use File::Spec ();

our $VERSION = '0.03';

# Where violations wait when the control plane cannot take them.
#
# The control plane will be unreachable sometimes - a deploy, a network
# partition, an expired certificate - and when it is, the gateway must
# keep proxying as if nothing had happened. That makes the spool's job
# unusual: it is not "do not lose data", it is B<do not become the
# problem>. In that order:
#
#   1. Never block the request path. A write here is one small local
#      file, and a write that fails is counted and forgotten.
#   2. Never grow without bound. Past the cap the oldest batch is
#      deleted and the drop is counted - so an outage costs the customer
#      the oldest violations, never the disk.
#   3. Then, and only then, keep what fits.
#
# One file per flushed window, written to a temporary name and renamed
# into place, so a reader never sees half a batch and a crash mid-write
# leaves a stray temp file rather than a corrupt one. The order is the
# filename: a monotonic counter, zero-padded, so a directory listing is
# the queue.

sub new {
    my ($class, %o) = @_;
    my $dir = $o{dir} or die "Maat::Spool: dir is required\n";

    my $self = bless {
        dir       => $dir,
        max_files => defined $o{max_files} ? $o{max_files} : 1000,
        max_bytes => defined $o{max_bytes} ? $o{max_bytes} : 64 * 1024 * 1024,
        encode    => $o{encode} || \&_encode_json,
        decode    => $o{decode} || \&_decode_json,
        seq       => 0,
        counters  => {
            spooled       => 0,   # batches written
            dropped       => 0,   # batches deleted to stay inside the bounds
            write_failed  => 0,   # batches that could not be written at all
            read_failed   => 0,   # files that could not be read back
        },
    }, $class;

    File::Path::make_path($dir) unless -d $dir;

    # Restart into an existing spool: carry on after the highest number
    # already there, so ordering survives a process that came back.
    for my $f ($self->_files) {
        my ($n) = $f =~ /(\d+)\.json\z/;
        $self->{seq} = $n if defined $n && $n > $self->{seq};
    }

    return $self;
}

sub dir      { $_[0]{dir} }
sub counters { $_[0]{counters} }

# The batches waiting, oldest first. A directory read, so callers that
# want it per request should not - the shipper asks on its own timer.
sub _files {
    my ($self) = @_;
    opendir my $dh, $self->{dir} or return ();
    my @f = sort grep { /\A[0-9]+\.json\z/ } readdir $dh;
    closedir $dh;
    return @f;
}

sub depth { scalar(($_[0]->_files)) }

sub bytes {
    my ($self) = @_;
    my $total = 0;
    for my $f ($self->_files) {
        my $size = (stat File::Spec->catfile($self->{dir}, $f))[7];
        $total += $size if defined $size;
    }
    return $total;
}

# Put a batch on the spool. Returns the filename, or undef when it could
# not be written - which is not an error the caller has to handle,
# because there is nothing useful it could do about it and the request it
# came from is long gone.
sub push_batch {
    my ($self, $records) = @_;
    return undef unless $records && @$records;

    my $body = eval { $self->{encode}->($records) };
    if (!defined $body) { $self->{counters}{write_failed}++; return undef }

    my $name = sprintf '%012d.json', ++$self->{seq};
    my $path = File::Spec->catfile($self->{dir}, $name);
    my $tmp  = "$path.tmp";

    my $ok = eval {
        open my $fh, '>', $tmp or die "open: $!";
        binmode $fh;
        print {$fh} $body or die "write: $!";
        close $fh or die "close: $!";
        rename $tmp, $path or die "rename: $!";
        1;
    };
    if (!$ok) {
        unlink $tmp;
        $self->{counters}{write_failed}++;
        return undef;
    }

    $self->{counters}{spooled}++;
    $self->_enforce_bounds;
    return $name;
}

# Delete oldest until the spool is inside both bounds. Deleting the
# oldest rather than refusing the newest is deliberate: during an outage
# the recent violations are the ones describing what is happening now.
sub _enforce_bounds {
    my ($self) = @_;
    my @f = $self->_files;

    while (@f > $self->{max_files}) {
        my $victim = shift @f;
        unlink File::Spec->catfile($self->{dir}, $victim);
        $self->{counters}{dropped}++;
    }

    return unless $self->{max_bytes};
    my $total = 0;
    my %size;
    for my $f (@f) {
        my $s = (stat File::Spec->catfile($self->{dir}, $f))[7];
        $size{$f} = defined $s ? $s : 0;
        $total += $size{$f};
    }
    while (@f > 1 && $total > $self->{max_bytes}) {
        my $victim = shift @f;
        unlink File::Spec->catfile($self->{dir}, $victim);
        $total -= $size{$victim};
        $self->{counters}{dropped}++;
    }
    return;
}

# The oldest batches, for shipping: a list of [ $name, \@records ]. The
# files stay until they are acknowledged, so a shipper that dies between
# reading and sending loses nothing.
sub take {
    my ($self, $n) = @_;
    $n = 10 unless defined $n && $n > 0;
    my @out;
    for my $f ($self->_files) {
        last if @out >= $n;
        my $path = File::Spec->catfile($self->{dir}, $f);
        my $records = eval {
            open my $fh, '<', $path or die "open: $!";
            binmode $fh;
            local $/;
            my $body = <$fh>;
            close $fh;
            $self->{decode}->($body);
        };
        if (!$records || ref $records ne 'ARRAY') {
            # Unreadable or not what we wrote. Removed rather than
            # retried forever: a file that cannot be parsed will not
            # start parsing, and leaving it would wedge the queue behind
            # it for as long as the process lives.
            $self->{counters}{read_failed}++;
            unlink $path;
            next;
        }
        push @out, [ $f, $records ];
    }
    return @out;
}

# Acknowledge: the control plane has these, so the spool need not.
sub done {
    my ($self, @names) = @_;
    unlink File::Spec->catfile($self->{dir}, $_) for @names;
    return;
}

# Everything the spool knows about itself, for /metrics.
sub stats {
    my ($self) = @_;
    return {
        %{ $self->{counters} },
        depth => $self->depth,
        bytes => $self->bytes,
    };
}

# ---- the default codec ------------------------------------------------------
# File::Raw::JSON when it is there (it is, in a gateway - Open::API
# requires it), and a refusal rather than a hand-rolled encoder if not.

sub _encode_json {
    my ($records) = @_;
    require File::Raw::JSON;
    return File::Raw::JSON::file_json_encode($records);
}

sub _decode_json {
    my ($body) = @_;
    return undef unless defined $body && length $body;
    require File::Raw::JSON;
    return File::Raw::JSON::file_json_decode($body);
}

1;

__END__

=head1 NAME

Maat::Spool - where violations wait when the control plane cannot take them

=head1 SYNOPSIS

    my $spool = Maat::Spool->new(dir => '/var/spool/maat',
                                 max_files => 1000,
                                 max_bytes => 64 * 1024 * 1024);

    $spool->push_batch(\@records);          # one flushed window

    for my $batch ($spool->take(10)) {
        my ($name, $records) = @$batch;
        $spool->done($name) if ship($records);
    }

=head1 DESCRIPTION

The control plane will be unreachable sometimes - a deploy, a partition,
an expired certificate - and while it is, the gateway must keep proxying
as though nothing had happened. That makes this component's job an
unusual one: it is not "do not lose data", it is B<do not become the
problem>. In that order:

=over 4

=item 1.

B<Never block the request path.> A write is one small local file, and a
write that fails is counted and forgotten - there is nothing useful the
caller could do about it, and the request it came from is long gone.

=item 2.

B<Never grow without bound.> Past the cap the oldest batch is deleted
and the drop counted, so an outage costs the customer their oldest
violations rather than their disk.

=item 3.

Then, and only then, keep what fits.

=back

Deleting the oldest rather than refusing the newest is deliberate:
during an outage, the recent violations are the ones describing what is
happening now.

=head2 On disk

One file per flushed window, written under a temporary name and renamed
into place, so a reader never sees half a batch and a crash mid-write
leaves a stray temporary file rather than a corrupt one. Order is the
filename - a zero-padded monotonic counter - so a directory listing is
the queue, and a restart carries on after the highest number it finds.

A file that cannot be parsed is deleted rather than retried: it will not
start parsing, and leaving it would wedge everything behind it for as
long as the process lives. The deletion is counted in C<read_failed>.

=head1 METHODS

=head2 new(dir => $path, max_files => 1000, max_bytes => 64MB)

=head2 push_batch(\@records)

Write one batch. Returns its name, or undef if it could not be written.

=head2 take($n) / done(@names)

The oldest batches as C<[ $name, \@records ]> pairs, and the
acknowledgement that removes them. Files stay until acknowledged, so a
shipper that dies between reading and sending loses nothing.

=head2 depth / bytes / counters / stats / dir

C<stats> is everything at once, for C</metrics>: C<spooled>, C<dropped>,
C<write_failed>, C<read_failed>, C<depth>, C<bytes>.

=cut
