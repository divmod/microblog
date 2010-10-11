--
-- This sequence will give us unique numbers for messages
-- Sequences are an Oracle-specific feature, but all databases
-- have something like them.
--
create sequence blog_message_id start with 1 increment by 1
                minvalue 0 nocycle cache 1024 noorder;

--
-- blog users.  Self explanatory
--
create table blog_users (
--
-- Each user must have a name and a unique one at that.
--
  name  varchar(64) not null primary key,
--
-- Each user must have a password of at least eight characters
--
-- Note - this keeps the password in clear text in the database
-- which is a bad practice and only useful for illustration
--
-- The right way to do this is to store an encrypted password
-- in the database
--
  password VARCHAR(64) NOT NULL,
    constraint long_passwd CHECK (password LIKE '________%'),
--
-- Each user must have an email address and it must be unique
-- the constraint checks to see that there is an "@" in the name
--
  email    varchar(256) not null UNIQUE
    constraint email_ok CHECK (email LIKE '%@%')
);


--
-- the list of things that a user can do
--
CREATE TABLE blog_actions (
  action VARCHAR(64) NOT NULL primary key
);

--
-- And the mapping from users to their actions
--
CREATE TABLE blog_permissions (
--
-- must be a current user on the system.  if a user is deleted
-- his permissions should be deleted with him
--
  name  VARCHAR(64) NOT NULL references blog_users(name)
     ON DELETE cascade,
--
-- must be a current action on the system.  if an action is deleted
-- then all permissions with that action must also be deleted
--
  action VARCHAR(64) NOT NULL references blog_actions(action)
     ON DELETE cascade,
--
-- name->action mappings must be unique
--
--
  constraint perm_unique UNIQUE(name,action)
);


--
-- The message
--
--
create table blog_messages (
--
-- unique identifier that must exist
--
  id number not null primary key,
--
-- the message to which it refers.  It must refer either to itself
-- or to some other message that exists.  A message cannot be removed from
-- the system unless it has no messages refering to it.
--
  respid number NOT NULL references blog_messages(id),
--
-- the author must be given and he/she must be a user
-- if an author is removed from the system
-- Authors cannot be removed from the system until all their messages are deleted
--
  author varchar(64) not null references blog_users(name),
--
-- It's OK if there is no subject
--
  subject VARCHAR(64),
--
-- message must have a timestamp
--
-- this is an SQL-style timestamp/date value:
--  time timestamp NOT NULL,
--
-- to make our lives easier, we are going to use a number which
-- represents seconds since the epoch (1970), which is the Unix
-- way of thinking about time.  
-- the Time::ParseDate module will make it easy to conversion 
-- between human readable dates and this format.
--
  time NUMBER NOT NULL,
--
--
--
-- text of message may not be empty
--
-- Oracle VARCHAR fields can be up to 4K in length.
-- To make longer fields, we would use CLOB or even BLOB
  text VARCHAR(2048) NOT NULL
);


--
-- Create a table for uploaded blog images (BLOB type)
--

create table blog_images (
	id number not null primary key references blog_messages(id),
	image BLOB not null
);

--
-- Create a set of actions
--
--
INSERT INTO blog_actions VALUES ('manage-users');
INSERT INTO blog_actions VALUES ('query-messages');
INSERT INTO blog_actions VALUES ('delete-any-messages');
INSERT INTO blog_actions VALUES ('delete-own-messages');
INSERT INTO blog_actions VALUES ('write-messages');


--
-- Create the required users
--
INSERT INTO blog_users (name,password,email) VALUES ('none','nonenone','none@none.com');
INSERT INTO blog_users (name,password,email) VALUES ('root','rootroot','root@root.com');

--
-- And what they can do  (root can do everything, none can do nothing)
--
INSERT INTO blog_permissions (name,action) VALUES('root','manage-users');
INSERT INTO blog_permissions (name,action) VALUES('root','query-messages');
INSERT INTO blog_permissions (name,action) VALUES('root','delete-any-messages');
INSERT INTO blog_permissions (name,action) VALUES('root','delete-own-messages');
INSERT INTO blog_permissions (name,action) VALUES('root','write-messages');


--
-- Create the very first message (0)
--
INSERT INTO blog_messages (id, respid, author, subject, time, text) VALUES (0,0,'none','none',0,'dummy');
B

quit;
