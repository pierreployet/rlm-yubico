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

use strict;
use warnings;
use vars qw(%RAD_REQUEST %RAD_REPLY %RAD_CHECK);
use Error qw(:try);

# for verifying OTPs via ykval
use HTTP::Tiny;
use MIME::Base64;
use Digest::HMAC_SHA1 qw(hmac_sha1);
use URI::Escape;
use Crypt::OpenSSL::Random qw(random_bytes random_status);


#Add script directory to @INC:
use File::Spec::Functions qw(rel2abs);
use File::Basename;
use lib dirname(rel2abs($0));

# Default configuration
our $id_len = 12;
our $verify_urls = [
	"https://api.yubico.com/wsapi/2.0/verify",
	"https://api2.yubico.com/wsapi/2.0/verify",
	"https://api3.yubico.com/wsapi/2.0/verify",
	"https://api4.yubico.com/wsapi/2.0/verify",
	"https://api5.yubico.com/wsapi/2.0/verify"
];
our $client_id = 10549;
our $api_key = "zeYjxHz+X/d12FAq0av4U9goZHY=";
our $allow_auto_provisioning = 1;
our $allow_userless_login = 1;
our $security_level = 0;
our $mapping_file = undef;

# Load user configuration
do "/etc/yubico/rlm/ykrlm-config.cfg";

# Initialization
my $otp_len = 32 + $id_len;

use YKmap;
if(defined $mapping_file) {
	YKmap::set_file($mapping_file);
}

########################
# FreeRADIUS functions #
########################

use constant    RLM_MODULE_REJECT=>    0;#  /* immediately reject the request */
use constant	RLM_MODULE_FAIL=>      1;#  /* module failed, don't reply */
use constant	RLM_MODULE_OK=>	2;#  /* the module is OK, continue */
use constant	RLM_MODULE_HANDLED=>   3;#  /* the module handled the request, so stop. */
use constant	RLM_MODULE_INVALID=>   4;#  /* the module considers the request invalid. */
use constant	RLM_MODULE_USERLOCK=>  5;#  /* reject the request (user is locked out) */
use constant	RLM_MODULE_NOTFOUND=>  6;#  /* user not found */
use constant	RLM_MODULE_NOOP=>      7;#  /* module succeeded without doing anything */
use constant	RLM_MODULE_UPDATED=>   8;#  /* OK (pairs modified) */
use constant	RLM_MODULE_NUMCODES=>  9;#  /* How many return codes there are */


# Make sure the user has a valid YubiKey OTP
sub authorize {

	# Extract OTP, if available
	my $otp = '';
	if($RAD_REQUEST{'User-Name'} =~ /[cbdefghijklnrtuv]{$otp_len}$/) {
		my $username_len = length($RAD_REQUEST{'User-Name'}) - $otp_len;
		$otp = substr $RAD_REQUEST{'User-Name'}, $username_len;
		$RAD_REQUEST{'User-Name'} = substr $RAD_REQUEST{'User-Name'}, 0, $username_len;
	} elsif($RAD_REQUEST{'User-Password'} =~ /[cbdefghijklnrtuv]{$otp_len}$/) {
		my $password_len = length($RAD_REQUEST{'User-Password'}) - $otp_len;
		$otp = substr $RAD_REQUEST{'User-Password'}, $password_len;
		$RAD_REQUEST{'User-Password'} = substr $RAD_REQUEST{'User-Password'}, 0, $password_len;
	}

	my $username = $RAD_REQUEST{'User-Name'};
	
	# Handle OTP
	if($otp eq '') {
		# No OTP
		if($username eq '') {
			# No OTP or username, reject
			&radiusd::radlog(1, "Reject: No username or OTP");
			$RAD_REPLY{'Reply-Message'} = "Missing username and OTP!";
			return RLM_MODULE_REJECT;
		} elsif($security_level eq 2 or ($security_level eq 1 and YKmap::has_otp($username))) {
			$RAD_REPLY{'Reply-Message'} = "Please provide YubiKey OTP";
			return RLM_MODULE_REJECT;
		} else {
			# Allow login without OTP
			&radiusd::radlog(1, "$username allowed with no OTP");
			return RLM_MODULE_NOOP;
		}
	} elsif(validate_otp($otp)) {
		&radiusd::radlog(1, "OTP is valid: $otp");

		my $public_id = substr($otp, 0, $id_len);

		#Lookup username if needed/allowed.
		if($username eq '' and $allow_userless_login) {
			$username = YKmap::lookup_username($public_id);
			&radiusd::radlog(1, "lookup of $public_id gave $username");
			$RAD_REQUEST{'User-Name'} = $username;
		}

		if(YKmap::key_belongs_to($public_id, $username)) {
			&radiusd::radlog(1, "$username has valid OTP: $otp");
			&radiusd::radlog(2, "Accepted OTP for $username from " . $RAD_REQUEST{'NAS-IP-Address'});
			return RLM_MODULE_OK;
		} elsif($allow_auto_provisioning and YKmap::can_provision($public_id, $username)) {
			&radiusd::radlog(1, "Attempt to provision $public_id for $username post authentication");
			$RAD_CHECK{'YubiKey-Provision'} = $public_id;
			return RLM_MODULE_UPDATED;	
		} else {
			&radiusd::radlog(2, "Rejected valid OTP from foreign YubiKey $public_id for $username from " . $RAD_REQUEST{'NAS-IP-Address'}); 
			$RAD_REPLY{'Reply-Message'} = "Invalid OTP!";
			return RLM_MODULE_REJECT;
		}
	} else {
		#Invalid OTP
		&radiusd::radlog(1, "Reject: $username with invalid OTP: $otp");
		&radiusd::radlog(2, "Rejected OTP for $username from " . $RAD_REQUEST{'NAS-IP-Address'});
		$RAD_REPLY{'Reply-Message'} = "Invalid OTP!";
		return RLM_MODULE_REJECT;
	}
}

# Do auto-provisioning, if needed, after authentication.
sub post_auth {
	my $public_id = $RAD_CHECK{'YubiKey-Provision'};
	my $username = $RAD_REQUEST{'User-Name'};

	if($public_id =~ /^[cbdefghijklnrtuv]{$id_len}$/) {
		YKmap::provision($public_id, $username);
	}

	return RLM_MODULE_OK;
}


sub authenticate {
	my $username = $RAD_REQUEST{'User-Name'};
	my $password = $RAD_REQUEST{'User-Password'};

	if(YKmap::verify_password($username, $password)) {
		&radiusd::radlog(2, "Accepted password for $username from " . $RAD_REQUEST{'NAS-IP-Address'});
		return RLM_MODULE_OK;
	}

	&radiusd::radlog(2, "Rejected password for $username from " . $RAD_REQUEST{'NAS-IP-Address'});

	# Same error message to user to reduce oracle attacks
	$RAD_REPLY{'Reply-Message'} = "Invalid OTP!";
 	return RLM_MODULE_REJECT;
} 


##################
# OTP Validation #
##################

# From AnyEvent::Yubico
# Parses a response body into a hash.
sub parse_response {
        my $body = shift;
        my $response = {};

        if($body) {
                my @lines = split(' ', $body);
                foreach my $line (@lines) {
                        my $index = index($line, '=');
                        $response->{substr($line, 0, $index)} = substr($line, $index+1);
                }
        }

        return $response;
}

# From AnyEvent::Yubico
# Signs a parameter hash using the client API key.
sub sign {
        my ($params) = @_;
        my $content = "";

        foreach my $key (sort keys %$params) {
                $content = $content."&$key=$params->{$key}";
        }
        $content = substr($content, 1);

        my $key = decode_base64($api_key);
        my $signature = encode_base64(hmac_sha1($content, $key), '');

        return $signature;
}

# Makes a cryptographically-strong nonce
# returns a string with 128 bits of entropy
sub make_nonce() {
	# bail out here if there's not enough entropy. better than using
	# non-random data!
	die("OpenSSL PRNG isn't adequately seeded. Also, do you have /dev/urandom?") if(!random_status());

	# 16 bytes = 128 bits
	# hex is fine.
	my $random = random_bytes(16);
	return sprintf("%s", unpack("H*",$random));
}

# Fetch a URL.
# Returns the body if success, undef otherwise
sub fetch_url($) {
	my $url = shift;

	# version check if running https.
	# old versions will silently ignore bad ssl certs.
	if(HTTP::Tiny->VERSION <= 0.012 && $url =~ /^\s*https/i) {
		die("Your version of HTTP::Tiny (" . HTTP::Tiny->VERSION . ") probably ignores bad ssl certs and will be vulnerable to a MITM attack.  Upgrade your package or uncomment this check if you accept this risk.");
	}

	my $response = HTTP::Tiny->new(timeout=>10, verify_ssl=> 1)->get($url);

	return undef unless($response->{success});

	return $response->{content};
}

# Validates a YubiKey OTP.
sub validate_otp {
	my($otp) = @_;

	# we'll use a different implementation to talk http since
	# AnyEvent::HTTP has nondeterministic behavior with rlm_perl 
	# and multiple threads.

	# similar logic to AnyEvent::Yubico verify_async
	# prepare parameters for request

	# AnyEvent::Yubico uses UUID::Tiny for the nonce.
	# This is NOT cryptographically strong.
	# We'll use OpenSSL's PRNG instead.
	my $nonce = make_nonce();

	my $params = {
		id => $client_id,
		nonce => $nonce,
		otp => $otp,
	};

	# sign request?
	my $signature = '';
	if($api_key ne '') {
		$signature = sign($params);
		$params->{h} = $signature;
	}

	# escape query string
	my $query = '';
	for my $key (keys %$params) {
		$query = "$query&$key=".uri_escape($params->{$key});
	}
	$query = "?".substr($query, 1);

	# validate the responses. stop on the first host to accept
	# note: a redundant configuration may cause one or more
	# validators to return REPLAYED_REQUEST, which is OK as long as
	# at least ONE validator returns OK.
	foreach my $url(@$verify_urls) {
		my $body = fetch_url("$url$query");
		next unless($body);
		
		my $response = parse_response($body);

		# check signature if availible
		if($api_key ne '') {
			my $signature = $response->{h};
			delete $response->{h};
			if(! $signature eq sign($response)) {
				$response->{status} = "BAD_RESPONSE_SIGNATURE";
				# this is something we want to know about.
				&radiusd::radlog(3, "BAD_RESPONSE_SIGNATURE from $url for NAS " . $RAD_REQUEST{'NAS-IP-Address'});
			}
		}

		# A redundant configuration may cause one or more validators 
		# to return REPLAYED_REQUEST, which is fine as long as
		# at least ONE validator returns OK.
		# thus, we can just ignore a REPLAYED_REQUEST response.
		next if($response->{status} eq "REPLAYED_REQUEST");

		# Here's the one case for success!
		return 1 if($response->{status} eq "OK" && $nonce eq $response->{nonce} && $otp eq $response->{otp});
	}

	# if we're still here, that means there's no chance of success.
	return 0;
}


# Encrypts a password using an instance specific key
sub encrypt_password {
	my($plaintext) = @_;

	# Crypt::CBC uses Carp in a way that blows up this module on 
	# Debian Wheezy.  It's probably OK to just pass the password back
	# to the client as-is, since it's 
	return $plaintext;
}

# Decrypts a password using an instance specific key
sub decrypt_password {
	my($ciphertext) = @_;
	return $ciphertext;
	#return $cipher->decrypt($ciphertext);
}
