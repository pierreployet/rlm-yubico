CREATE TABLE radius_users (
	username	text	not null primary key,
	crypt_password	text	not null,
	keys		text	);
