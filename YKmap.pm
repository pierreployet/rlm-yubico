# Copyright (c) 2013 Yubico AB
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#   * Redistributions in binary form must reproduce the above
#     copyright notice, this list of conditions and the following
#     disclaimer in the documentation and/or other materials provided
#     with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package YKmap;

use strict;
use Fcntl qw(:flock :seek);

# let's use SQLite to make scripting maintenance easier.
use DBI;

my $file = '/etc/yubico/rlm/ykmapping';

sub set_file {
	$file = shift;
}

sub _read_data {
	my $data = {};
	if(open(MAP_FILE, $file)) {
		while(my $line = <MAP_FILE>) {
			chomp($line);
			next if $line =~ /^(#|$)/;

			my ($username, $keystring) = split(/:/, $line, 2);
			my @keys = split(/,/, $keystring);
			$data->{$username} = \@keys;
		}
		close(MAP_FILE);
	}
	return $data;
}

# emulate _read_data's output, but only fetch info for the supplied username
sub _read_data_sqlite($) {
	my $username = shift;
	my $data = {};

	# don't bother doing work if input is junk
	return {} unless($username && $username ne '');

	# this might die(). we don't want that, so fail-safe instead.
	eval {
		my $dbh = DBI->connect($file, "", "", { AutoCommit => 1, PrintWarn => 0, PrintError => 0}) or die($!);
		my $sth = $dbh->prepare("SELECT username,crypt_password,keys from radius_users where username = ? order by username") or die($dbh->errstr);
		$sth->execute($username) or die($dbh->errstr);
		
		my @row = $sth->fetchrow_array();

		die("Unknown user: $username") unless(scalar @row); # not found

		# we'll pack the password as the first item in the array
		# hopefully the caller knows what to do with it.
		my @keys = split(/,/, $row[2]);
		unshift(@keys, $row[1]);

		$data->{$row[0]} = \@keys;

		$sth->finish();
		undef $dbh;
	};

	# if something goes wrong, return 'not found'
	# that's probably the least likely to cause trouble
	if($@) {
		warn $@;
		return {};
	}

	return $data;
}

# get a list of possible usernames associated with a public id
# make sure to confirm with 'key_belongs_to', as the results are
# just a loose match.
# returns candidates as keys to a hash, to emulate _read_data()
sub _suggest_usernames_sqlite($) {
	my $key = shift;
	my $data = {};

	# don't bother doing work if input is junk
	return {} unless($key && $key ne '');

	# this might die(). we don't want that, so fail-safe instead.
	eval {
		my $dbh = DBI->connect($file, "", "", { AutoCommit => 1, PrintWarn => 0, PrintError => 0}) or die($!);
		my $sth = $dbh->prepare("SELECT username, crypt_password, keys from radius_users where keys like ? order by username") or die($dbh->errstr);
		$sth->execute("%$key%") or die($dbh->errstr);
	
		while(my @row = $sth->fetchrow_array()) {
			my @keys = split(/,/, $row[2]);
			unshift(@keys, $row[1]);
			$data->{$row[0]} = \@keys;
		}

		$sth->finish();
		undef $dbh;
	};
	
	# if something goes wrong, return 'not found'
	# that's probably the least likely to cause trouble
	if($@) {
		warn("Unknown key/public id: $key (Detail: $@)");
		return {};
	}
	return $data;
}

# Check if a particular username has an OTP assigned to him/her.
sub has_otp {
	my($username) = @_;
	
	my $data;

	# use sqlite if file looks like a DSN
	if($file =~ /^dbi:SQLite:dbname/) {
		$data = _read_data_sqlite($username);
	} else {
		$data = _read_data();
	}

	return exists($data->{$username});
}

# Checks if the given public id comes from a YubiKey belonging to the 
# given user.
sub key_belongs_to {
	my($public_id, $username, $data) = @_;

	# use sqlite if file looks like a DSN
	if($file =~ /^dbi:SQLite:dbname/) {
		$data = _read_data_sqlite($username) unless defined $data;
	} else {
		$data = _read_data() unless defined $data;
	}

	foreach my $x (@{$data->{$username}}) {
		next if($x =~ /^$/);  # skip IDs that look like crypted passwords
		if($x eq $public_id) {
			return 1;
		}
	}
	return 0;
}

# Returns the username for the given YubiKey public ID.
sub lookup_username {
	my($public_id) = @_;
	my $data;

	# use sqlite if file looks like a DSN
	if($file =~ /^dbi:SQLite:dbname/) {
		$data = _suggest_usernames_sqlite($public_id);
	} else {
		$data = _read_data();
	}

	foreach my $user (keys $data) {
		if(key_belongs_to($public_id, $user, $data)) {
			return $user;
		}
	}

	return undef;
}

# Verify a password
# returns 0 for failure, 1 for success
sub verify_password($$) {
	my($username, $plain_password) = @_;

	my $data;

	# sorry, no empty passwords.
	return 0 unless(length $plain_password);

	# use sqlite if file looks like a DSN
	if($file =~ /^dbi:SQLite:dbname/) {
		$data = _read_data_sqlite($username);
	} else {
		$data = _read_data();
	}
	return 0 unless($data);

	# the password, if present, is the first item in the keys array.
	if(exists($data->{$username}) && defined($data->{$username}[0]) && length $data->{$username}[0]) {
		my $crypt_password = crypt($plain_password, $data->{$username}[0]);
		return 1 if($crypt_password eq $data->{$username}[0]);
	}

	return 0;
}

# Can we auto-provision the given YubiKey for the user?
sub can_provision {
	my($public_id, $username) = @_;

	my $data;

	#TODO: Check if key is provisioned to someone else?

	# use sqlite if file looks like a DSN
	if($file =~ /^dbi:SQLite:dbname/) {
		$data = _read_data_sqlite($username);
	} else {
		$data = _read_data();
	}

	return not exists($data->{$username});
}

# Provision the given YubiKey to the given user.
sub provision {
	my($public_id, $username) = @_;

	
	# We don't support provisioning into an SQLite DB yet.
	if($file =~ /^dbi:SQLite:dbname/) {
		warn("Provisioning into SQLite not supported!");
		warn("Unable to provision YubiKey: $public_id to $username!");
		return;
	}

	if(open(MAP_FILE,">>$file")) {
		flock(MAP_FILE, LOCK_EX);
		seek(MAP_FILE, 0, SEEK_END); 
		print MAP_FILE "$username:$public_id\n"; 
		close(MAP_FILE);
	} else {
		warn("Unable to provision YubiKey: $public_id to $username!");
	}
}

1;
