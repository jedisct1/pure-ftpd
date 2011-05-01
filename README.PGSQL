
       ----------------------- PostgreSQL SUPPORT ------------------------


When PostgreSQL is enabled, all account info is fetched from a central Potgres
database.

To compile the server with PostgreSQL support, you first have to build and
install the PostgreSQL client libraries. PostgreSQL is freely available from
http://www.postgresql.org/ and binary packages are included in many major
distributions. But if you choose a binary form, don't forget to also install
the development packages if they are available separately.

Then, configure Pure-FTPd with --with-pgsql and your favorite extra gadgets:


    ./configure --with-pgsql --with-cookie --with-throttling --with-ratios


If your PostgreSQL libraries are installed in a special path, you can specify
it like this:


    ./configure --with-pgsql=/opt/pgsql


In this example, headers (like pgsql.h) will be searched in
/opt/pgsql/include and /opt/pgsql/include/pgsql, while related libraries
will be searched in /opt/pgsql/lib and /opt/pgsql/lib/pgsql .

Then, install the server as usual:


                                 make install


 ------------------------ PGSQL CONFIGURATION FILE ------------------------
           

Before running the server, you have to create a configuration file. Why a
configuration file instead of simple command-line options? you may ask.
Because for security reasons, you may want to hide how to connect to your
PostgreSQL server. And as command-line options can be discovered by local users
(with 'ps auxwww' for instance), it's more secure to use a configuration
file for sensitive data. Keep it readable only by root (chmod 600) .

Here's a sample configuration file:

PGSQLServer     localhost
PGSQLPort       5432
PGSQLUser       root
PGSQLPassword   rootpw
PGSQLDatabase   pureftpd
PGSQLCrypt      cleartext
PGSQLGetPW      SELECT "Password" FROM "users" WHERE "User"='\L'
PGSQLGetUID     SELECT "Uid" FROM "users" WHERE "User"='\L'
PGSQLGetGID     SELECT "Gid" FROM "users" WHERE "User"='\L'
PGSQLGetDir     SELECT "Dir" FROM "users" WHERE "User"='\L'

Have a look at the sample pureftpd-pgsql.conf configuration file for
explanations of every keyword.

Save the configuration file anywhere. Let's say /etc/pureftpd-pgsql.conf .

Then, you have to run the pure-ftpd command with '-l pgsql:' (it's an 'ell'
not a 'one') followed by the path of that configuration file. Here's an
example with tcpserver:


tcpserver -DHRl0 0 21 /usr/local/bin/pure-ftpd -l pgsql:/etc/pureftpd-pgsql.conf &


You can mix different authentication methods. For instance, if you want to
use system (/etc/passwd) accounts when an account is not found in a PostgreSQL
database, use -l pgsql:/etc/pureftpd-pgsql.conf -l unix


     ------------------------ TABLES STRUCTURES ------------------------
     
     
Pure-FTPd is very flexible and users can be stored in any way in SQL tables.
You just have to have fields with the following info:

- The user's login.

- The user's password, in plaintext, crypt()ed format, MD5 or SHA1.
Pure-FTPd also accepts the "any" value for the PGSQLCrypt field.
With "any", all hashing functions (not plaintext) are tried.

- The system uid to map the user to. This can be a numeric id or a user
name, looked up at run-time.

- The system gid (numeric or not) .

- The home directory.

Here's a dump of a simple table to handle this:

CREATE TABLE "users" (
  "User" VARCHAR(16) NOT NULL,
  "Password" VARCHAR(64) BINARY NOT NULL,
  "Uid" INTEGER NOT NULL default '-1',
  "Gid" INTEGER NOT NULL default '-1',
  "Dir" VARCHAR(128) NOT NULL,
  PRIMARY KEY ("User")
) WITHOUT OIDS;

Uid and Gid can be VARCHAR instead of INTEGER if you want to use names instead
of values.

Then, in the pureftpd-pgsql.conf configuration file, you have to provide SQL
templates to fetch the needed info.

Let's take the previous example:

PGSQLGetPW      SELECT "Password" FROM "users" WHERE "User"='\L'
PGSQLGetUID     SELECT "Uid" FROM "users" WHERE "User"='\L'
PGSQLGetGID     SELECT "Gid" FROM "users" WHERE "User"='\L'
PGSQLGetDir     SELECT "Dir" FROM "users" WHERE "User"='\L'

For each query:

\L is replaced by the login of a user trying to authenticate.
\I is replaced by the IP address the client connected to.
\P is replaced by the port number the client connected to.
\R is replaced by the remote IP address the client connected from.
\D is replaced by the remote IPv4 address, as a long decimal number.

You can mix all of these to store info in various tables. For instance, with
\I, you can have a different table for every domain, so that joe@domain1
won't be the same account than joe@domain2 . And with \R, you can restrict
one account to one specific address.

Please note that a login can only contains common characters: A...Z, a...z,
0...9, -, ., _, space, :, @ and  and ' . For security purposes, other
characters are forbidden.

You can also remove uid and gid fields in your tables and use default
values instead (thus saving useless lookups) . Two directives are
useful to serve that purpose: PGSQLDefaultUID and PGSQLDefaultGID.

Obvious example:

PGSQLDefaultUID 1000
PGSQLDefaultGID 1000

Using these directives overrides PGSQLGetUID and PGSQLGetGID.


     ------------------------ PER-USER SETTINGS ------------------------


Individual settings can be set for every user, using optional queries.

- PGSQLGetQTAFS is the maximal number of files a user can store in his home
directory.

Example:
PGSQLGetQTAFS SELECT "QuotaFiles" FROM "users" WHERE "User"='\L'

- PGSQLGetQTASZ is the maximal disk usage, in Megabytes.

Example:
PGSQLGetQTASZ SELECT "QuotaSize" FROM "users" WHERE "User"='\L'

- PGSQLGetRatioUL and PGSQLGetRatioDL are optional ratios.

Example:
PGSQLGetRatioUL SELECT "ULRatio" FROM "users" WHERE "User"='\L'
PGSQLGetRatioDL SELECT "DLRatio" FROM "users" WHERE "User"='\L'

- PGSQLGetBandwidthUL and PGSQLGetBandwidthDL are optional upload and
download bandwidth restrictions. Returned values should be in KB/s.

Example:
PGSQLGetBandwidthUL SELECT "ULBandwidth" FROM "users" WHERE "User"='\L'
PGSQLGetBandwidthDL SELECT "DLBandwidth" FROM "users" WHERE "User"='\L'



      ------------------------ ANONYMOUS USERS ------------------------


If you want to accept anonymous users on your FTP server, you don't need to
have any 'ftp' user in the PGSQL directory. But you need to have a system
'ftp' account on the FTP server.


        ------------------------ ROOT USERS ------------------------


If a PGSQL user entry has a root (0) uid and/or gid, Pure-FTPd will refuse
to log him in.

Without this preventive restriction, if your PGSQL server ever gets
compromised, the attacker could also easily compromise the FTP server.

Security barriers are also implemented to avoid bad implications if wrong
data types (eg. binary blobs instead of plain text) are fetched with SQL
queries.


Hint:

PostgreSQL supports views and it's common practice to define a new DB
user, e.g., ftpd and a view of the 'real' user database with just the
bits that the server needs. E.g., if you have virtual domains you
could use:

create view vftpd as select u.vuser, u.domain, u.passwd, d.uid, d.gid,
'/virtual/' || u.domain || '/' || u.vuser || '/./' as homedir
from vusers as u, vdomains as d where u.domain = v.domain;

grant select on vftpd to ftpd;

The definition of homedir shows how views can be used to enforce a
canonical form for home directories - nothing short of defining this
view will allow a user to drop the chroot from their home directory.
