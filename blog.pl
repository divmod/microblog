#!/usr/bin/perl -w
use POSIX;
#
# Some debugging options
# all of this debugging info will be shown at the *end* of script
# execution.
#
# database input and output is paired into the two arrays noted
#
my $show_params=1;
my $show_cookies=1;
my $show_sqlinput=1;
my $show_sqloutput=1;
my @sqlinput=();
my @sqloutput=();

#
# The combination of -w and use strict enforces various 
# rules that make the script more resilient and easier to run
# as a CGI script.
#
use strict;

# The CGI web generation stuff
# This helps make it easy to generate active HTML content
# from Perl
#
# We'll use the "standard" procedural interface to CGI
# instead of the OO default interface
use CGI qw(:standard);

# The interface to the database.  The interface is essentially
# the same no matter what the backend database is.  
#
# DBI is the standard database interface for Perl. Other
# examples of such programatic interfaces are ODBC (C/C++) and JDBC (Java).
#
#
# This will also load DBD::Oracle which is the driver for
# Oracle.
use DBI;

#
#
# A module that makes it easy to parse relatively freeform
# date strings into the unix epoch time (seconds since 1970)
#
use Time::ParseDate;

use URI::Escape;


#
# The following is necessary so that DBD::Oracle can
# find its butt
#
$ENV{ORACLE_HOME}="/opt/oracle/product/11.2.0/db_1";
$ENV{ORACLE_BASE}="/opt/oracle/product/11.2.0";
$ENV{ORACLE_SID}="CS339";

#
# You need to override these for access to your database
#
my $dbuser="jhb348";
my $dbpasswd="ob5e18c77";
#my $dbuser="drp925";
#my $dbpasswd="o3d7f737e";

#
# The session cookie will contain the user's name and password so that 
# he doesn't have to type it again and again.
#
# "MicroblogSession"=>"user/password"
#
# BOTH ARE UNENCRYPTED AND THE SCRIPT IS ALLOWED TO BE RUN OVER HTTP
# THIS IS FOR ILLUSTRATION PURPOSES.  IN REALITY YOU WOULD ENCRYPT THE COOKIE
# AND CONSIDER SUPPORTING ONLY HTTPS
#
my $cookiename="MicroblogSession";

#
# Get the session input cookie, if any
#
my $inputcookiecontent = cookie($cookiename);

#
# Will be filled in as we process the cookies and paramters
#
my $outputcookiecontent = undef;
my $deletecookie=0;
my $user = undef;
my $password = undef;
my $loginok=0;
my $logincomplain=0;


#
#
# Get action user wants to perform
#
my $action;
if (param("act")) { 
  $action=param("act");
} else {
  $action="login";
}

#
# Is this a login request or attempt?
# Ignore cookies in this case.
#
if ($action eq "login" || param('loginrun')) { 
  if (param('loginrun')) { 
    #
    # Login attempt
    #
    # Ignore any input cookie.  Just validate user and
    # generate the right output cookie, if any.
    #
    ($user,$password)=(param('user'),param('password'));
    if (ValidUser($user,$password)) { 
      # if the user's info is OK, then give him a cookie
      # that contains his username and password 
      # the cookie will expire in one hour, forcing him to log in again
      # after one hour of inactivity.
      # Also, land him in the query screen
      $outputcookiecontent=join("/",$user,$password);
      $loginok=1;
    } else {
      # uh oh.  Bogus login attempt.  Make him try again.
      # don't give him a cookie
      $logincomplain=1;
      $action="login";
    }
  } else {
    #
    # Just a login screen request. Still, ignore any cookie that's there.
    #
  }
} else {
  #
  # Not a login request or attempt.  Only let this past if
  # there is a cookie, and the cookie has the right user/password
  #
  if ($inputcookiecontent) {
    # if the input cookie exists, then grab it and sanity check it
    ($user,$password) = split(/\//,$inputcookiecontent);
    if (!ValidUser($user,$password)) { 
      # Bogus cookie.  Make him log in again.
      $action="login";
      # don't give him an output cookie
    } else {
      # cookie is OK, give him back the refreshed cookie
      $outputcookiecontent=$inputcookiecontent;
    }
  } else {
    #
    # He has no cookie and must log in.
    #
    $action="login";
  }
}


#
# If we are being asked to log out, then if 
# we have a cookie, we should delete it.
#
if ($action eq "logout") {
  $deletecookie=1;
}




#
# OK, so now we have user/password
# and we *may* have a cookie.   If we have a cookie, we'll send it right 
# back to the user.
#
# We force the expiration date on the generated page to be immediate so
# that the browsers won't cache it.
#
if ($outputcookiecontent) { 
  my $cookie=cookie(-name=>$cookiename,
		    -value=>$outputcookiecontent,
		    -expires=>($deletecookie ? '-1h' : '+1h'));
  print header(-expires=>'now', -cookie=>$cookie);
} else {
  print header(-expires=>'now');
}

#
# Now we finally begin spitting back HTML
#
#
print start_html('Microblog');

#
# This tells the web browser to render the page in the style
# defined in the blog.css file
#

print "<style type=\"text/css\">\n\@import \"blog.css\";\n</style>\n";


if ($loginok) { 
  print "<h2>You have successfully logged in</h2>";
}

#
#
# The remainder here is essentially a giant switch statement based
# on $action.  In response to an action, we will put up one or more forms.
# Each form contains a hidden parameter that lets us know whether the 
# script is being called with form contents. If we are getting form contents
# we also generate the output following it
#
#


# LOGIN
#
# Login is a special case since we handle the filled out form up above
# in the cookie-handling code.  So, here we only put up the form.
# 
#
if ($action eq "login") { 
  if ($logincomplain) { 
    print "Login failed.  Try again.<p>"
  } 
  if ($logincomplain or !param('loginrun')) { 
    print start_form(-name=>'Login'),
      h2('Login to Microblog'),
	"Name:",textfield(-name=>'user'),	p,
	  "Password:",password_field(-name=>'password'),p,
	    hidden(-name=>'act',default=>['login']),
	      hidden(-name=>'loginrun',default=>['1']),
		submit,
		  end_form;
  }
}

if ($action eq "logout") { 
  print "<h2>You have been successfully logged out</h2>";
}

# 
#
# Query is a "normal" form.
#
#
if ($action eq "query") {
  #
  # check to see if user can see this
  #
  my $page = param('page');
  my $flag = param('flag');
  if (!UserCan($user,"query-messages")) { 
    print h2('You do not have the required permissions to query messages.');
  } else {
    #
    # Generate the form
    # This is the part you will be extending
    #
    print start_form(-name=>'Query'),
      h2('Display blog entries'),
	"From: ", textfield(-name=>'from',-default=>'yesterday'),
	  "To: ", textfield(-name=>'to',-default=>'now'),
	    p, "By: ", textfield('by'),
			p, "Subject: ", textfield('subject'),
			p, "Content: ", textfield('content'),
			p
	      hidden(-name=>'queryrun',default=>['1']),
		hidden(-name=>'act',default=>['query']),
		hidden(-name=>'page',default=>['1']),
		  submit,
		 
		    end_form;
    #
    # if we have the hidden parameter queryrun, then we have
    # been invoked with data
    #
     #Msg per page
      my $msgPerPage = 5;
      
    if (param('queryrun') || $flag) {
      my $from=param('from');
      my $to=param('to');
      my $by=param('by');
      my $subj=param('subject');
      my $content=param('content');
      my $page = param('page');
      $flag = 1;
      #if($param('flag'); 
      #
      # Run the query (note, you need to write MessageQuery!)
      # to actually use the parameters.  Right now it just returns all
      # the messages.
      #
      my ($mq,$count, $error) = MessageQuery($from,$to,$by,$subj,$content, $page, $msgPerPage);
#      print "count=".$count;
      my $p = getPagination($msgPerPage, $page, $count, $flag);
      print $p;
      if ($error ) { 
	print "Can't query messages because: $error";
      } else {
	print $mq;
      }
    } else {
      #
      # If we haven't been invoked with parameters, then just
      # display a message summary.  You will update this to give
      # a tree display
      #
       
      
      #Determine how many rows from the query
            
      $flag = 0;
      my $numRows = totalRows();
      #Determine the num of pages
      my $numPages = ceil($numRows/$msgPerPage);
      my $i;
      #my $page = 1;
      my $end = $msgPerPage * $page;
      my $p = getPagination($msgPerPage, $page, $numRows, $flag);
      #for($i = 1; $i <= $numRows; $i = $i + $msgPerPage){
	#print $i;
	#print " ";
	#print $i + $msgPerPage;
	print $p;
        my ($ms,$error)=MessageSummary($end, $msgPerPage, $numRows);
        if ($error) { 
	  print "Can't summarize messages because: $error";
        } else {
	  print $ms;
        }
	#$page++;
      #}#end for
    }#end if param query run
  }#end else of usercan
}#END ACTION QUERY

# WRITE
#
# Write is a "normal" form.
#
#
if ($action eq "write") { 
  #
  # check to see if user can see this
  #
  if (!UserCan($user,"write-messages")) { 
    print h2('You do not have the required permissions to write messages.');
  } else {
    #
    # Generate the form.
    # Your reply functionality will be similar to this
    #
    print start_multipart_form(-name=>'Write'),
      h2('Make blog entry'),
	"Subject:", textfield(-name=>'subject'),
	  p,
	  textarea(-name=>'post', 
		   -default=>'Write your post here.',
		   -rows=>16,
		   -columns=>80),
          hidden(-name=>'postrun',-default=>['1']),
	  hidden(-name=>'act',-default=>['write']), p
		filefield(-name=>'img',
			-default=>'startingvalue',
			-size=>50,
			-maxlength=>80),p
	  submit,
	  end_form,
	  hr;

    #
    # If we're being invoked with parameters, then
    # do the actual posting. 
    #
    if (param('postrun')) { 
      my $by=$user;
      my $text=param('post');
      my $subject=param('subject');
			my $file=param('img');

			if (defined ($file) && $file ne "") {
				
				open(LOCAL, ">$file") or die $!;
				while(<$file>) {
					print LOCAL $_;
				}
				close(LOCAL);
				
				my $error=Post(0,$by,$subject,$text);
	    	if ($error) { 
					print "Can't post message because: $error";
		    } else {
					print "Posted the following on the $subject from $by:<p>$text<p>";
				}
				my $id = GetId($by,$subject,$text);
				print $id."<p>";
				my $bloberror=BlobInsert($dbuser, $dbpasswd, $id, $file);
				if ($bloberror) {
					print "Can't post message with upload image because: $bloberror";
				} else {
					print "Successfully posted and uploaded the image.";
				}
				unlink($file);
			}
			else {
				my $error=Post(0,$by,$subject,$text);
	      if ($error) { 
					print "Can't post message because: $error";
	      } else {
					print "Posted the following on $subject from $by:<p>$text<p>";
				}
      }
    }
  }
}



#	DELETE
#
# Deleting messages
#
#
if ($action eq "delete" || param('deleterun')) { # deleterun = 1 in delete call
	my $id = param('id'); # param('id')? or something else?
	if (MsgOwner($user,$id) && UserCan($user,"delete-own-messages") || (UserCan($user,"delete-any-messages"))) {
		if (HasRef($id)) {
			print h2('Message cannot be deleted because other messages refer to it.');
		}
		else {
		# delete the message
	  eval {ExecSQL($dbuser,$dbpasswd,"delete from blog_messages where id=?", undef, $id);};
		print h2('Message has been deleted.');
		}
 	}
	else {
		# print error statement
		print h2('You do not have the required permissions to delete this message.');
	}
}


# REPLY
#
# Replying to messages
#
#
if ($action eq "reply") {
	my $respid = param('respid');
	# print $respid;
	if(UserCan($user,"write-messages")) {
    #
    # Generate the form.
    # Your reply functionality will be similar to this
    #
    print start_form(-name=>'Reply'),
      h2('Reply to a blog entry'),
	"Subject:", textfield(-name=>'subject'),
	  p,
	  textarea(-name=>'reply', 
		   -default=>'Write your reply here.',
		   -rows=>16,
		   -columns=>80),
          hidden(-name=>'postrun',-default=>['1']),
					hidden(-name=>'respid',-default=>[$respid]),
	  hidden(-name=>'act',-default=>['reply']), p
		filefield(-name=>'img',
			-default=>'startingvalue',
			-size=>50,
			-maxlength=>80),p

submit,
	  end_form,
	  hr;

    #
    # If we're being invoked with parameters, then
    # do the actual posting. 
    #
    if (param('postrun')) { 
      my $by=$user;
      my $text=param('reply');
      my $subject=param('subject');
			my $respid=param('respid');


			my $file=param('img');

			if (defined ($file) && $file ne "") {
				
				open(LOCAL, ">$file") or die $!;
				while(<$file>) {
					print LOCAL $_;
				}
				close(LOCAL);
				
				my $error=Post($respid,$by,$subject,$text);
	    	if ($error) { 
					print "Can't post message because: $error";
		    } else {
					print "Posted the following on the $subject from $by:<p>$text<p>";
				}
				my $id = GetId($by,$subject,$text);
				print $id."<p>";
				my $bloberror=BlobInsert($dbuser, $dbpasswd, $id, $file);
				if ($bloberror) {
					print "Can't post message with upload image because: $bloberror";
				} else {
					print "Successfully posted and uploaded the image.";
				}
				unlink($file);
			}
			else {

			# print "Response id: $respid";
      my $error=Post($respid,$by,$subject,$text);
      if ($error) { 
	print "Can't post message because: $error";
      } else {
	print "Posted the following on $subject in response to message $respid from $by:<p>$text";
      }
			}
    }
	}
	else {
		print h2('You do not have the required permissions to write a message.');
	}
}



#
# IMAGE
#
# Displaying an image from the database
#
if ($action eq "image") {
# is a check necessary for permissions?
# just display the image
# assume the id param passed has already went through the check for having an image
	my $id = param('id');
	my $imgdata = BlobExtract($dbuser,$dbpasswd,$id);
#	print $imgdata;
	my $filename = $id.".jpg";
#	print $filename;
	open(LOCAL,">$filename");
	binmode(LOCAL);
	print LOCAL $imgdata;
	close(LOCAL);
	print "<img src=\"$filename\">";
}



# USERS
#
# Adding and deleting users is a couple of normal forms
#
#
if ($action eq "users") { 
  #
  # check to see if user can see this
  #
  if (!UserCan($user,"manage-users")) { 
    print h2('You do not have the required permissions to manage users.');
  } else {
    #
    # Generate the add form.
    #
    print start_form(-name=>'AddUser'),
      h2('Add User'),
    "Name: ", textfield(-name=>'name'),
      p,
    "Email: ", textfield(-name=>'email'),
      p,
    "Password: ", textfield(-name=>'password'),
      p,
	hidden(-name=>'adduserrun',-default=>['1']),
          hidden(-name=>'act',-default=>['users']),
	  submit,
	       end_form,
		 hr;
    #
    # Generate the givepermform.
    #
    print start_form(-name=>'GivePermission'),
      h2('Give Permission'),
      "Name: ", textfield(-name=>'name'),
	p,
      "Action: ", textfield(-name=>'perm'),
	  hidden(-name=>'givepermrun',-default=>['1']),
          hidden(-name=>'act',-default=>['users']),p,
	  submit,
	       end_form,
	    hr;

    #
    # Generate the revokepermform.
    #
    print start_form(-name=>'RevokePermission'),
      h2('Revoke Permission'),
      "Name: ", textfield(-name=>'name'),
	p,
      "Action: ", textfield(-name=>'perm'),
	  hidden(-name=>'revokepermrun',-default=>['1']),
          hidden(-name=>'act',-default=>['users']),p,
	  submit,
	       end_form,
	    hr;

    #
    # Generate the deleteform.
    # Your delete message functionality may be similar to this
    #
    print start_form(-name=>'DeleteUser'),
      h2('Delete User'),
      "Name: ", textfield(-name=>'name'),
	p,
	  hidden(-name=>'deluserrun',-default=>['1']),
          hidden(-name=>'act',-default=>['users']),
	  submit,
	       end_form,
	    hr;

    #
    # Run the user add
    #
    if (param('adduserrun')) { 
      my $name=param('name');
      my $email=param('email');
      my $password=param('password');
      my $error;
      $error=UserAdd($name,$password,$email);
      if ($error) { 
	print "Can't add user because: $error";
      } else {
	print "Added user $name $email\n";
      }
    }
    #
    # Run the user delete
    #
    if (param('deluserrun')) { 
      my $name=param('name');
      my $error=UserDel($name);
      if ($error) { 
	print "Can't delete user because: $error";
      } else { 
	print "User $name deleted.";
      }
    }
    #
    # Run givepermission
    #
    if (param('givepermrun')) { 
      my $name=param('name');
      my $perm=param('perm');
      my $error=GiveUserPerm($name,$perm);
      if ($error) { 
	print "Can't give $name permission $perm because: $error";
      } else { 
	print "User $name given permission $perm.";
      }
    }
    #
    # Run givepermission
    #
    if (param('revokepermrun')) { 
      my $name=param('name');
      my $perm=param('perm');
      my $error=RevokeUserPerm($name,$perm);
      if ($error) { 
	print "Can't revoke $name permission $perm because: $error";
      } else { 
	print "User $name has had permission $perm revoked.";
      }
    }
    #
    # Print tables users Permissions
    #
    my ($table,$error);
    ($table,$error)=PermTable();
    if ($error) { 
      print "Can't display permissions table because: $error";
    } else {
      print "<h2>Available Permissions</h2>$table";
    }
    ($table,$error)=UserTable();
    if ($error) { 
      print "Can't display user table because: $error";
    } else {
      print "<h2>Registered Users</h2>$table";
    }
    ($table,$error)=UserPermTable();
    if ($error) { 
      print "Can't display user permission table because: $error";
    } else {
      print "<h2>Users and their permissions</h2>$table";
    }
  }
}

#
# Generate debugging output if anything is enabled.
#
#
if ($show_params || $show_cookies || $show_sqlinput || $show_sqloutput) { 
  print hr, p, hr,p, h2('Debugging Output');
  if ($show_params) { 
    print h3('Parameters');
    print "<menu>";
    print map { "<li>$_ => ".param($_)} param();
    print "</menu>";
  }
  if ($show_cookies) { 
    print h3('Cookies');
    print "<menu>";
    print map { "<li>$_ => ".cookie($_)} cookie();
    print "</menu>";
  }
  if ($show_sqlinput || $show_sqloutput) { 
    my $max= $show_sqlinput ?  $#sqlinput : $#sqloutput;
    print h3('SQL');
    print "<menu>";
    for (my $i=0;$i<=$max;$i++) { 
      if ($show_sqlinput) { print "<li><b>Input:</b> $sqlinput[$i]";}
      if ($show_sqloutput) { print "<li><b>Output:</b> $sqloutput[$i]";}
    }
    print "</menu>";
  }
} 

print end_html;

#
# The main line is finished at this point. 
# The remainder includes utilty and other functions
#


#
# Generate a table of available permissions
# ($table,$error) = PermTable()
# $error false on success, error string on failure
#
sub PermTable {
  my @rows;
  eval { @rows = ExecSQL($dbuser, $dbpasswd, "select action from blog_actions"); }; 
  if ($@) { 
    return (undef,$@);
  } else {
    return (MakeTable("2D",
		     ["Perm"],
		     @rows),$@);
  }
}

#
# Generate a table of users
# ($table,$error) = UserTable()
# $error false on success, error string on failure
#
sub UserTable {
  my @rows;
  eval { @rows = ExecSQL($dbuser, $dbpasswd, "select name, email from blog_users order by name"); }; 
  if ($@) { 
    return (undef,$@);
  } else {
    return (MakeTable("2D",
		     ["Name", "Email"],
		     @rows),$@);
  }
}

#
# Generate a table of users and their permissions
# ($table,$error) = UserPermTable()
# $error false on success, error string on failure
#
sub UserPermTable {
  my @rows;
  eval { @rows = ExecSQL($dbuser, $dbpasswd, "select blog_users.name, blog_permissions.action from blog_users, blog_permissions where blog_users.name=blog_permissions.name order by blog_users.name"); }; 
  if ($@) { 
    return (undef,$@);
  } else {
    return (MakeTable("2D",
		     ["Name", "Permission"],
		     @rows),$@);
  }
}

#
# Add a user
# call with name,password,email
#
# returns false on success, error string on failure.
# 
# UserAdd($name,$password,$email)
#
sub UserAdd { 
  eval { ExecSQL($dbuser,$dbpasswd,
		 "insert into blog_users (name,password,email) values (?,?,?)",undef,@_);};
  return $@;
}

#
# Delete a user
# returns false on success, $error string on failure
# 
sub UserDel { 
  eval {ExecSQL($dbuser,$dbpasswd,"delete from blog_users where name=?", undef, @_);};
  return $@;
}


#
# Give a user a permission
#
# returns false on success, error string on failure.
# 
# GiveUserPerm($name,$perm)
#
sub GiveUserPerm { 
  eval { ExecSQL($dbuser,$dbpasswd,
		 "insert into blog_permissions (name,action) values (?,?)",undef,@_);};
  return $@;
}

#
# Revoke a user's permission
#
# returns false on success, error string on failure.
# 
# RevokeUserPerm($name,$perm)
#
sub RevokeUserPerm { 
  eval { ExecSQL($dbuser,$dbpasswd,
		 "delete from blog_permissions where name=? and action=?",undef,@_);};
  return $@;
}

#
#
# Check to see if user and password combination exist
#
# $ok = ValidUser($user,$password)
#
#
sub ValidUser {
  my ($user,$password)=@_;
  my @col;
  eval {@col=ExecSQL($dbuser,$dbpasswd, "select count(*) from blog_users where name=? and password=?","COL",$user,$password);};
  if ($@) { 
    return 0;
  } else {
    return $col[0]>0;
  }
}


#
#
# Check to see if user can do some action
#
# $ok = UserCan($user,$action)
#
sub UserCan {
  my ($user,$action)=@_;
  my @col;
  eval {@col= ExecSQL($dbuser,$dbpasswd, "select count(*) from blog_permissions where name=? and action=?","COL",$user,$action);};
  if ($@) { 
    return 0;
  } else {
    return $col[0]>0;
  }
}

sub HasRef {
	my ($id) = @_;
	my @col;
	eval {@col=ExecSQL($dbuser,$dbpasswd,"select count(*) from blog_messages where respid=?","COL",$id);};
	if ($@) {
		return 0;
	} else {
		return $col[0]>0;
	}
}


sub HasImg {
	my($id) = @_;
	my @col;
	eval {@col=ExecSQL($dbuser,$dbpasswd,"select count(*) from blog_images where id=?","COL",$id);};
	if ($@) {
		return 0;
	} else {
		return $col[0]>0;
	}
}




sub totalRows{
  my @rows;
  my $size;
	eval {@rows=ExecSQL($dbuser,$dbpasswd,"select author,subject,time,id,id from blog_messages");};
	if ($@) {
		return 0;
	} else {
	        $size = scalar @rows;
	        #print $size;
		return $size;
	}
  
}

sub MsgOwner {
	my ($user,$id)=@_;
	my @col;
	eval {@col=ExecSQL($dbuser,$dbpasswd,"select count(*) from blog_messages where author=? and id=?","COL",$user,$id);};
	if ($@) {
		return 0;
	} else {
		return $col[0]>0;
	}
}


sub GetId {
	my ($by, $subject, $text) = @_;
	my @col;
	eval{@col=ExecSQL($dbuser, $dbpasswd, "select id from blog_messages where author=? and subject=? and text=?","COL",$by, $subject, $text);};
	if($@) {
		return 0;
	} else {
		return $col[0];
	}
}

sub GetImg {
	my ($id) = @_;
	my @col;
	eval{@col=ExecSQL($dbuser, $dbpasswd, "select image from blog_images where id=?", "COL",$id);};
	if ($@) {
		return 0;
	} else {
		return $col[0];
	}
}

#
# Post a message
#
# returns false if success, error string if failed.
#
# Post($respid, $author, $subject, $text);
#
# $respid => "response id", the id of the message to which you are responding.
#            zero if you are not responding to a message
# $author, $subject, $text => self-explanatory
#
sub Post { 
  my ($respid,$author, $subject, $text) = @_;

#
# this idiom, eval and then $@, is an exception handling trick in perl
# even if ExecSQL dies, the eval will succeed.  At the end of the 
# eval, $@ will either be false or will contain the string with which
# die was called.
#
  eval { ExecSQL($dbuser,$dbpasswd,"insert into blog_messages (id,respid,author,subject,time,text) ".
		 "select blog_message_id.nextval, ?, ?, ?, ?, ? from dual",
		undef, $respid, $author, $subject, time(), $text); };
  return $@ ;
}


#
# Generate a summary of messages (a table of all messages in the system)
# You will extend this to support showing a tree of messages and also
# within other constraints
#
# ($table,$error) = MessageSummary();
#
sub MessageSummary {
  #print "Came here";
  my ($end, $msgPerPage, $numrows) = @_;
  my @rows;
  #
  #calculate the number of pages
  #
  #print $msgPerPage. " ";
  #print $numrows. " ";
  #print $page. " ";
  
   my $start = $end - $msgPerPage + 1;
   #$end = $start + $msgPerPage - 1;
   
    if($end > $numrows){
      $end = $numrows;
    }

    #print "end:". $end;
    #where id<>0 order by time
    #eval { @rows = ExecSQL($dbuser,$dbpasswd,
     #                   "select author,subject,time,id,id from blog_messages where rownum between ? and ? order by time",undef,$start, $end);};
    eval { @rows = ExecSQL($dbuser,$dbpasswd,
                          "select author,subject,time,id,id from
			  (SELECT x.author, x.subject, x.time, x.id, rownum as r FROM
			  (select author,subject,time,id,rownum from blog_messages order by time DESC)x)
			   where r between ? and ? and id <>0",undef,$start, $end);};
   # print @rows;
    if ($@) {
      #print "I came here";
      return (undef,$@);
    } else {
    
       
		    
      # Convert time values to pretty printed version
      #print @rows;
      foreach my $r (@rows) {
			$r->[2]=localtime($r->[2]);
			$r->[3]="<a href=blog.pl?act=delete&deleterun=1&id=$r->[3]>delete</a>";
			$r->[4]="<a href=blog.pl?act=reply&respid=$r->[4]>reply</a>";
  		}
      return (MakeTable("2D", ["Author","Subject","Time","Delete?","Reply?"],@rows),$@);
    }

}

#
# Generate a list of messages that match the criteria 
# Currently, this is ignores the criteria and shows all messages
# You will fix this.
#
# ($html,$error) = MessageQuery($from,$to,$by,$subj,$content)
#
sub MessageQuery {
  my ($from, $to, $by, $subj, $content, $page, $msgPerPage) = @_;
  
  my $timefrom=parsedate($from);
  my $timeto=parsedate($to);

  my @msgs;

	if ($by ne "") {
		if ($from ne "") {
			if ($to ne "") {
			      if($subj ne ""){
				  if($content ne ""){
				    ##author from to title content
				    eval {@msgs=ExecSQL($dbuser,$dbpasswd,"select id, respid, author, subject, time, text from blog_messages where time between ? and ? and regexp_like(author,?,'i') and regexp_like(subject,?, 'i') and regexp_like(text,?,'i') order by time DESC",undef,$timefrom,$timeto,$by,$subj,$content);};
				  }
				  else{
				    ##author from to title
				    eval {@msgs=ExecSQL($dbuser,$dbpasswd,"select id, respid, author, subject, time, text from blog_messages where time between ? and ? and regexp_like(author,?,'i') and regexp_like(subject,?,'i') order by time DESC",undef,$timefrom,$timeto,$by,$subj);};
				  }
			      }#end of subj
			      else{
				##author from to
				eval {@msgs=ExecSQL($dbuser,$dbpasswd,"select id, respid, author, subject, time, text from blog_messages where time between ? and ? and regexp_like(author,?,'i') order by time DESC",undef,$timefrom,$timeto,$by);};
			      }
			}#end of $to
			else {
			    if($subj ne ""){
			        if($content ne ""){
			      	  ##author from title content
				  eval {@msgs=ExecSQL($dbuser,$dbpasswd,"select id, respid, author, subject, time, text from blog_messages where time >=? and regexp_like(author,?,'i') and regexp_like(subject,?, 'i') and regexp_like(text,?,'i') order by time DESC",undef,$timefrom,$by,$subj,$content);};
				}
				else{
				  #author from title 
				  eval {@msgs=ExecSQL($dbuser,$dbpasswd,"select id, respid, author, subject, time, text from blog_messages where time >=? and regexp_like(author,?,'i') and regexp_like(subject,?,'i') order by time DESC",undef,$timefrom,$by,$subj);};
			       }
			    }#end of subj
			    else{
			      ##author from
			       eval {@msgs=ExecSQL($dbuser,$dbpasswd,"select id, respid, author, subject, time, text from blog_messages where time >=? and regexp_like(author,?,'i') order by time DESC",undef,$timefrom,$by);};
			    }
			}
		}#end $from
		
		elsif ($to ne "") {
			if($subj ne ""){
				if($content ne ""){
				    #author to title content
				    eval {@msgs=ExecSQL($dbuser,$dbpasswd,"select id, respid, author, subject, time, text from blog_messages where time <=? and regexp_like(author,?,'i') and regexp_like(subject,?, 'i') and regexp_like(text,?,'i') order by time DESC",undef,$timeto,$by,$subj,$content);};
				}
				else{
				  #author to title
				  eval {@msgs=ExecSQL($dbuser,$dbpasswd,"select id, respid, author, subject, time, text from blog_messages where time <=? and regexp_like(author,?,'i') and regexp_like(subject,?,'i') order by time DESC",undef,$timeto,$by,$subj);};
				}
			}#end of subj	
			else{
			  ##author to
			  eval {@msgs=ExecSQL($dbuser,$dbpasswd,"select id, respid, author, subject, time, text from blog_messages where time <=? and regexp_like(author,?,'i') order by time DESC",undef,$timeto,$by);};
			  
			}
		}#end $to
		elsif ($subj ne ""){
			if($content ne ""){
			  #author title content
			  eval {@msgs=ExecSQL($dbuser,$dbpasswd,"select id, respid, author, subject, time, text from blog_messages where regexp_like(author,?,'i') and regexp_like(subject,?, 'i') and regexp_like(text,?,'i') order by time DESC",undef,$by,$subj,$content);};
			}
			else{
			  #author title 
			  eval {@msgs=ExecSQL($dbuser,$dbpasswd,"select id, respid, author, subject, time, text from blog_messages where regexp_like(author,?,'i') and regexp_like(subject,?,'i') order by time DESC",undef,$by,$subj);};
			}
			      
		}
		else {
		  #author
		  eval {@msgs=ExecSQL($dbuser,$dbpasswd,"select id, respid, author, subject, time, text from blog_messages where regexp_like(author,?,'i') order by time DESC",undef,$by);};
		}
	}#end $by
	elsif ($from ne "") {
		      if ($to ne "") {
			      if($subj ne ""){
				  if($content ne ""){
				    ##from to title content
				    eval {@msgs=ExecSQL($dbuser,$dbpasswd,"select id, respid, author, subject, time, text from blog_messages where time between ? and ? and regexp_like(subject,?, 'i') and regexp_like(text,?,'i') order by time DESC",undef,$timefrom,$timeto,$subj,$content);};
				  }
				  else{
				    ##from to title
				    eval {@msgs=ExecSQL($dbuser,$dbpasswd,"select id, respid, author, subject, time, text from blog_messages where time between ? and ? and regexp_like(subject,?,'i') order by time DESC",undef,$timefrom,$timeto,$subj);};
				  }
			      }#end of subj
			      else{
				##from to
				eval {@msgs=ExecSQL($dbuser,$dbpasswd,"select id, respid, author, subject, time, text from blog_messages where time between ? and ? order by time DESC",undef,$timefrom,$timeto);};
			      }
			}#end of $to
		      else {
			    if($subj ne ""){
			        if($content ne ""){
			      	  ##from title content
				  eval {@msgs=ExecSQL($dbuser,$dbpasswd,"select id, respid, author, subject, time, text from blog_messages where time >=? and regexp_like(subject,?, 'i') and regexp_like(text,?,'i') order by time DESC",undef,$timefrom,$subj,$content);};
				}
				else{
				  #from title 
				  eval {@msgs=ExecSQL($dbuser,$dbpasswd,"select id, respid, author, subject, time, text from blog_messages where time >=? and regexp_like(subject,?,'i') order by time DESC",undef,$timefrom,$subj);};
			       }
			    }#end of subj
			    else{
			       ##from
			       eval {@msgs=ExecSQL($dbuser,$dbpasswd,"select id, respid, author, subject, time, text from blog_messages where time>=? order by time DESC",undef,$timefrom);};
			    }
		      }

	}#end $from
	elsif ($to ne "") {
			if($subj ne ""){
				if($content ne ""){
				    #to title content
				    eval {@msgs=ExecSQL($dbuser,$dbpasswd,"select id, respid, author, subject, time, text from blog_messages where time <=? and regexp_like(subject,?, 'i') and regexp_like(text,?,'i') order by time DESC",undef,$timeto,$subj,$content);};
				}
				else{
				  #to title
				  eval {@msgs=ExecSQL($dbuser,$dbpasswd,"select id, respid, author, subject, time, text from blog_messages where time <=? and regexp_like(subject,?,'i') order by time DESC",undef,$timeto,$subj);};
				}
			}#end of subj	
			else{
			  ##to
			  eval {@msgs=ExecSQL($dbuser,$dbpasswd,"select id, respid, author, subject, time, text from blog_messages where time <=? order by time DESC",undef,$timeto);};
			  
			}
	}#end $to
	elsif($subj ne ""){
			if($content ne ""){
			    ##title content
			    eval {@msgs=ExecSQL($dbuser,$dbpasswd,"select id, respid, author, subject, time, text from blog_messages where regexp_like(subject,?, 'i') and regexp_like(text,?,'i') order by time DESC",undef,$subj,$content);};
		         }
			else{
			  ##title
			  eval {@msgs=ExecSQL($dbuser,$dbpasswd,"select id, respid, author, subject, time, text from blog_messages where regexp_like(subject,?, 'i') order by time DESC",undef,$subj);};
			}
	    
	  
	}#end $subj
	elsif($content ne ""){
	  ##content
	  eval {@msgs=ExecSQL($dbuser,$dbpasswd,"select id, respid, author, subject, time, text from blog_messages where regexp_like(text,?, 'i') order by time DESC",undef,$content);};
	}#end $content
	else {
	  ##nothing specified
	  eval {@msgs=ExecSQL($dbuser,$dbpasswd,"select id, respid, author, subject, time, text from blog_messages where id<>0 order by time DESC");};
	}#end nothing specified

# Original line: ignores criteria to show all messages
# eval {@msgs=ExecSQL($dbuser,$dbpasswd,"select id, respid, author, subject, time, text from blog_messages where id<>0 order by time");};

  if ($@) {  
    print "An error occured processing the SQL statement\n";
    return (undef,$@);
  } else {
    my $msg;
    my $out="";
    $out.="<h3>Messages from $from to $to by '$by'<h3>";
    if ($#msgs<0) { 
      $out.="There are no messages";
    }
    
    my $i;
    my $end = $page * $msgPerPage;
  #  print "end:".$end."<p>";
   
    my $start = $end - $msgPerPage + 1;
   #  print "start:".$start."<p> ";
    my $count = scalar @msgs;
    if($end > $count){
      $end = $count;
    }
    #print "msgs: ".$msgs." ";
    for($i = $start - 1; $i < $end; $i++){
    #foreach $msg (@msgs) {
    #  print "i:".$i."<p>";

      my ($id, $respid, $author, $subject, $time, $text) = @{$msgs[$i]};
      $out.="<table border><tr><td><b>id:</b></td><td>$id</td><td><b>respid:</b></td><td>$respid</td><td><b>Time:</b></td><td>".localtime($time)."</td></tr>";
      $out.="<tr><td><b>author:</b></td><td colspan=5>$author</td></tr>";
      $out.="<tr><td><b>subject:</b></td><td colspan=5>$subject</td></tr>";
      $out.="<tr><td colspan=6>$text</td></tr>";
			if(HasImg($id)) {
				$out.="<tr><td colspan=6><a href=\"blog.pl?act=image&id=$id\">Attached Image</a></td></tr>";
			}
			$out.="<tr><td colspan=3><a href=blog.pl?act=delete&deleterun=1&id=$id>delete</a></td><td colspan=3><a href=blog.pl?act=reply&respid=$id>reply</a></td></tr>";
      $out.="</table>";
    }
    return ($out, $count, $@);
  }
}

#
# Given a list of scalars, or a list of references to lists, generates
# an html table
#
#
# $type = undef || 2D => @list is list of references to row lists
# $type = ROW   => @list is a row
# $type = COL   => @list is a column
#
# $headerlistref points to a list of header columns
#
#
# $html = MakeTable($type, $headerlistref,@list);
#
sub MakeTable {
  my ($type,$headerlistref,@list)=@_;
  my $out;
  #
  # Check to see if there is anything to output
  #
  
  if ((defined $headerlistref) || ($#list>=0)) {
  
    # if there is, begin a table
    #
  
    $out.="<table border>";
    #
    # if there is a header list, then output it in bold
    #
    if (defined $headerlistref) { 
      $out.="<tr>".join("",(map {"<td><b>$_</b></td>"} @{$headerlistref}))."</tr>";
    }
    #
    # If it's a single row, just output it in an obvious way
    #
    if ($type eq "ROW") { 
      #
      # map {code} @list means "apply this code to every member of the list
      # and return the modified list.  $_ is the current list member
      #
      $out.="<tr>".(map {"<td>$_</td>"} @list)."</tr>";
    } elsif ($type eq "COL") { 
      #
      # ditto for a single column
      #
      $out.=join("",map {"<tr><td>$_</td></tr>"} @list);
    } else { 
      #
      # For a 2D table, it's a bit more complicated...
      #
      $out.= join("",map {"<tr>$_</tr>"} (map {join("",map {"<td>$_</td>"} @{$_})} @list));
    }
    $out.="</table>";
    #$out.="Hello World";
   
  } else {
    # if no header row or list, then just say none.
    $out.="(none)";
  }
  return $out;
}

#
# @list=ExecSQL($user, $password, $querystring, $type, @fill);
#
# Executes a SQL statement.  If $type is "ROW", returns first row in list
# if $type is "COL" returns first column.  Otherwise, returns
# the whole result table as a list of references to row lists.
# @fill are the fillers for positional parameters in $querystring
#
# ExecSQL executes "die" on failure.
#
sub ExecSQL {
  my ($user, $passwd, $querystring, $type, @fill) =@_;
  if ($show_sqlinput) { 
    # if we are recording inputs, just push the query string and fill list onto the 
    # global sqlinput list
    push @sqlinput, "$querystring (".join(",",map {"'$_'"} @fill).")";
  }
  my $dbh = DBI->connect("DBI:Oracle:",$user,$passwd);
  if (not $dbh) { 
    # if the connect failed, record the reason to the sqloutput list (if set)
    # and then die.
    if ($show_sqloutput) { 
      push @sqloutput, "<b>ERROR: Can't connect to the database because of ".$DBI::errstr."</b>";
    }
    die "Can't connect to database because of ".$DBI::errstr;
  }
  my $sth = $dbh->prepare($querystring);
  if (not $sth) { 
    #
    # If prepare failed, then record reason to sqloutput and then die
    #
    if ($show_sqloutput) { 
      push @sqloutput, "<b>ERROR: Can't prepare '$querystring' because of ".$DBI::errstr."</b>";
    }
    my $errstr="Can't prepare $querystring because of ".$DBI::errstr;
    $dbh->disconnect();
    die $errstr;
  }
  if (not $sth->execute(@fill)) { 
    #
    # if exec failed, record to sqlout and die.
    if ($show_sqloutput) { 
      push @sqloutput, "<b>ERROR: Can't execute '$querystring' with fill (".join(",",map {"'$_'"} @fill).") because of ".$DBI::errstr."</b>";
    }
    my $errstr="Can't execute $querystring with fill (".join(",",map {"'$_'"} @fill).") because of ".$DBI::errstr;
    $dbh->disconnect();
    die $errstr;
  }
  #
  # The rest assumes that the data will be forthcoming.
  #
  #
  my @data;
  if (defined $type and $type eq "ROW") { 
    @data=$sth->fetchrow_array();
    $sth->finish();
    if ($show_sqloutput) {push @sqloutput, MakeTable("ROW",undef,@data);}
    $dbh->disconnect();
    return @data;
  }
  my @ret;
  while (@data=$sth->fetchrow_array()) {
    push @ret, [@data];
  }
  if (defined $type and $type eq "COL") { 
    @data = map {$_->[0]} @ret;
    $sth->finish();
    if ($show_sqloutput) {push @sqloutput, MakeTable("COL",undef,@data);}
    $dbh->disconnect();
    return @data;
  }
  $sth->finish();
  if ($show_sqloutput) {push @sqloutput, MakeTable("2D",undef,@ret);}
  $dbh->disconnect();
  return @ret;
}

#pagination
# PHP pagination code by Stranger Studios (http://www.strangerstudios.com/).
# Converted to Perl by Andrew, 2006.

sub getPagination {
	my (#$adjacents, # How many adjacent pages should be shown on each side?
		$limit, # Number of items you will show per page.
		$page, # The current starting page.
		$total_items, # The total number of items you are paginating.
		#$scriptName, # The name of the CGI script in <a href="$scriptName?page=...">.
		#$extra # A string with any extra CGI params to include, of the form "&parm1=value1&parm2=value2&...".
		$flag
		) = @_;
	
	$page = 1 if ($page == 0);		# if no page var is given, default to 1.
	my $prev = $page - 1;							# previous page is page - 1
	my $next = $page + 1;							# next page is page + 1
	my $lastpage = ceil($total_items/$limit);		# lastpage is = total pages / items per page, rounded up.
	#my $lpm1 = $lastpage - 1;						# last page minus 1
			
	# Now we apply our rules and draw the pagination object. 
	# We're actually saving the HTML to a variable in case we want to draw it more than once.
	my $pagination = "<center><h3>";
	my $counter = 0;
	if ($lastpage > 1) {
		$pagination .= "<h2><div class=\"pagination\">";
		
		#first page
		$pagination .= "<a href=\"blog.pl?act=query&page=1&flag=$flag\">first</a>\     ";
		# previous button
		if ($page > 1) {
			$pagination .= "<a href=\"blog.pl?act=query&page=$prev&flag=$flag\">|\ « previous\     </a>";
			#$pagination .= "\&nsbp\;\&nsbp\;\&nsbp\;";
			
		}
		else{
		        #print "came here\n";
			$pagination .= "<span class=\"pagination_disabled\">|\ previous</span>";
		}
		$pagination .= "\     ";
		if($page < $lastpage){
		  $pagination .= "<a href=\"blog.pl?act=query&page=$next&flag=$flag\">|\ next »</a>\     ";
		}
		
		else{
			$pagination .= "<span class=\"pagination_disabled\"> |\ next</span>";
		}
		#first page
		$pagination .= "<a href=\"blog.pl?act=query&page=$lastpage&flag=$flag\">|\ last</a>\     ";
	  
		$pagination .= "</div><h3></center>";
	}
	#print $pagination . "--------\n";
	$pagination .= "</center>";
	return $pagination;
}



sub BlobExtract {
	my ($user, $passwd, $id) = @_;
	my ($dbh, $sth, $data);

	$dbh = DBI->connect("DBI:Oracle:",$user,$passwd) or die "connect failed: $DBI::errstr\n";
	$dbh->{'LongReadLen'}=2**20;
	$sth = $dbh->prepare("select image from blog_images where id=$id") or die "Can't prepare: $DBI::errstr\n";
	$sth->execute() or die "execute failed: $DBI::errstr\n";
	($data) = $sth->fetchrow_array();
	$sth->finish();
	$dbh->disconnect();
	return $data;
}

#
# @list=BlobInsert($user, $password, $respid, $author, $subject, $text, $filename);
# combines with: Post($respid, $author, $subject, $text)
# Executes a SQL statement for Blobs.  If $type is "ROW", returns first row in list
# if $type is "COL" returns first column.  Otherwise, returns
# the whole result table as a list of references to row lists.
# @fill are the fillers for positional parameters in $querystring
#
# BlobInsert executes "die" on failure.
#
sub BlobInsert {
	my ($user, $passwd, $id,$filename) = @_;
	my ($dbh, $sth, $size, $buf, $n);
	$size = (stat ($filename))[7];
	open (BLOB,$filename);
	$n = read(BLOB, $buf, $size);
	print "Number of characters read: $n";
	close(BLOB);
	$dbh = DBI->connect("DBI:Oracle:",$user,$passwd) or die "connect failed: $DBI::errstr\n";
	$dbh->{'LongReadLen'}=2**20;
#	$sth = $dbh->prepare("insert into blog_messages (id,respid,author,subject,time,text) select blog_message_id.nextval, $respid, '$author', '$subject', $time, '$text' from dual"); 
#	$sth->execute() or die "post failed: $DBI::errstr\n";
	$sth = $dbh->prepare("insert into blog_images values ($id,:temp)") or die "prepare failed: $DBI::errstr\n";
	$sth->bind_param(":temp",$buf, {ora_type=>24} ) or die "Can't bind: $DBI::errstr\n";
	$sth->execute() or die "execute failed: $DBI::errstr\n";
#	$sth->finish();

	my @data;
#  if (defined $type and $type eq "ROW") { 
#    @data=$sth->fetchrow_array();
#    $sth->finish();
#    if ($show_sqloutput) {push @sqloutput, MakeTable("ROW",undef,@data);}
#    $dbh->disconnect();
#    return @data;
#  }
  my @ret;
  while (@data=$sth->fetchrow_array()) {
    push @ret, [@data];
  }
#  if (defined $type and $type eq "COL") { 
#    @data = map {$_->[0]} @ret;
#    $sth->finish();
#    if ($show_sqloutput) {push @sqloutput, MakeTable("COL",undef,@data);}
#    $dbh->disconnect();
#    return @data;
#  }
  $sth->finish();
  if ($show_sqloutput) {push @sqloutput, MakeTable("2D",undef,@ret);}
  $dbh->disconnect();
  return @ret;

# $dbh->disconnect();
}
