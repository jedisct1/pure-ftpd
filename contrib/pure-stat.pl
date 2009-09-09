#!/usr/bin/perl
#--------------------------------------------------------------
# PROJECT : pure-ftpd statistics
# FILE : pure-stat.pl
# DESCRIPTION : see below (Purpose)
# AUTHOR : Chill
# DATE : 08/01/2002
# COMMENT:
# PARAMETER : none
# FROM FILE : none
#--------------------------------------------------------------
# PURPOSE
# get the log file $CONST_LOGFILE
# parse it and generate stats
# to avoid loading a huge log file, a summary file ($CONST_SUMFILE),
# is generated
#--------------------------------------------------------------
# TO DO
# - clean ugly code
#--------------------------------------------------------------

#CONSTANT DELCARATION
my $CONST_USER=0;
my $CONST_TUPLOAD=1;
my $CONST_TDOWNLOAD=2;
my $CONST_LCONNECTION=3;
my $CONST_LOGFILE="/var/log/pureftpd.log";
my $CONST_SUMFILE="/var/log/pureftpd.stat.log";

#FUNCTION DECLARATION
sub castSize;	

#CREATE USERS ARRAY (UGLY, BUT USEFUL FOR DISPLAY)
my @users = (["login", "upload", "download", "last connection"]);

#MAIN VARIABLES INIT
my $total_upload = 0;
my $total_download = 0;


#FUNCTION DEFINITION

#MODIFY 1234bytes => 1.2Mb...
sub castSize
{
	my $value = shift;

       	if ($value > 1073741824)
       	{
       	        $value = $value / 1073741824;
       	        @fvalue = ($value, "Gb");
       	}
       	elsif ($value > 1048576)
       	{
       	        $value = $value / 1048576;
       	        @fvalue = ($value, "Mb");
       	}
	elsif ($value > 1024)
       	{
       	        $value = $value / 1024;
       	        @fvalue = ($value, "Kb");
       	}
       	else
       	{
       	        @fvalue = ($value, "b");
       	}
	return @fvalue;
}
#END sub castSize

#LOAD SUMMARY FILE INTO ARRAY
open(SUMF,$CONST_SUMFILE);
my @sumlist = <SUMF>;
close SUMF;

#PARSING SUMMARY FILE INTO ARRAY
foreach $sumentry (@sumlist)
{
	($slogin, $sbytes_ul, $sbytes_dl, $sdate) =  $sumentry =~ m/^(\S+) (\S+) (\S+) \[([^\]\[]+)\]/;
	push @users, [$slogin, $sbytes_ul, $sbytes_dl, $sdate];
	$total_upload += $sbytes_ul;
	$total_download += $sbytes_dl;
}

#DEBUG# CHECKING ARRAY CONTENT
#for $i ( 1 .. $#users )
#{
#        $dactual_upload = $users[$i][$CONST_TUPLOAD];
#        $dactual_download = $users[$i][$CONST_TDOWNLOAD];
#
#        #PRINT ON STDOUT
#        printf "%s\t|\t%d\t\t|\t%d\t\t|\t%s\n", ($users[$i][$CONST_USER],$dactual_upload,$dactual_download,$users[$i][$CONST_LCONNECTION]);
#}
#END DEBUG#

#LOAD LOG FILE INTO ARRAY
open(LOG,$CONST_LOGFILE);
my @loglist = <LOG>;
close LOG;

#PARSING  ARRAY IF NOT EMPTY
if ($#loglist != -1)
{
	#GENERATE FILE EXTENSTION AS yearmonthmdayhourmin
	@dlist = gmtime(time);
	$ext = sprintf("%02d%02d%02d%02d%02d", $dlist[5], $dlist[4]+1, $dlist[3], $dlist[2]+2, $dlist[1]);
	undef @dlist;

	#WE BACKUP THE LOG FILE
	system ("gzip $CONST_LOGFILE -S .$ext.gz && touch $CONST_LOGFILE");

	foreach $logentry (@loglist)
	{
		#LET'S GRAB THE LOG ENTRY
		($ip, $tiret, $login, $date, $request, $status, $bytes) =  $logentry =~ m/^(\S+) (\S+) (\S+) \[([^\]\[]+)\] \"([^"]*)\" (\S+) (\S+)/; 
		
		#DEBUG STRING
		#print "ip = $ip| tiret = $tiret| login = $login| date = $date| request = $request| status = $status| bytes = $bytes\n\n";
		#print "login = $login| request = $request| bytes = $bytes\n";
	
		#ADD OR MODIFY USERS
		#IS THE USER IN THE SUMMARY FILE
		my $gotuser = 0;
		my $indexuser = 0;
	
		for $i ( 1 .. $#users )
		{
			if ($users[$i][$CONST_USER] eq $login)
			{
				$gotuser = 1;
				$indexuser = $i;
				last;
			}
		}
		
		#YES, WE DON'T ADD HIM, WE UPGRADE HIM
		if ($gotuser)
		{
			if ( $request =~ "PUT")
			{
			#UPLOAD CASE
				$users[$indexuser][$CONST_TUPLOAD] += $bytes;
				$total_upload += $bytes;
			}
			elsif ( $request =~ "GET")
			{
			#DOWNLOAD CASE
				$users[$indexuser][$CONST_TDOWNLOAD] += $bytes;
				$total_download += $bytes;
			}
			#LAST CONNECTION
			$users[$indexuser][$CONST_LCONNECTION] = $date;
		}
		else
		{
		#NOPE, WE ADD HIM
			if ( $request =~ "GET")
			{
			#DOWNLOAD CASE
				push @users, [$login, 0, $bytes, $date];
				$total_download += $bytes;
			}
			elsif ( $request =~ "PUT")
			{
			#UPLOAD CASE
				push @users, [$login, $bytes, 0, $date];
				$total_upload += $bytes;
			}
		}
	}
}
	
#PRINT RESULTS
#LET'S CLEAN THE SUMMARY FILE
system ("rm -f $CONST_SUMFILE && touch $CONST_SUMFILE");

#TABLE HEADER
print "----------------------------------------------\n";
print "$users[$i][$CONST_USER]\t|\t$users[$i][$CONST_TUPLOAD]\t\t|\t$users[$i][$CONST_TDOWNLOAD]\t\t|\t$users[$i][$CONST_LCONNECTION]\n";
print "----------------------------------------------\n";

#TABLE BODY
for $i ( 1 .. $#users )
{
        if ($total_upload <= 0)
        {
                $percent_upload=0;
        } else {
		$percent_upload= 100*$users[$i][$CONST_TUPLOAD]/$total_upload;
        }
        if ($total_download <= 0)
        {
                $percent_download=0;
        } else {
		$percent_download= 100*$users[$i][$CONST_TDOWNLOAD]/$total_download;
	}

	@actual_upload = castSize $users[$i][$CONST_TUPLOAD];
	@actual_download = castSize $users[$i][$CONST_TDOWNLOAD];

	$strLogin = sprintf "%s", $users[$i][$CONST_USER];
	$strUl = sprintf "%.1f %s (%.1f%%)", ($actual_upload[0],$actual_upload[1],$percent_upload);
	$strDl = sprintf "%.1f %s (%.1f%%)", ($actual_download[0],$actual_download[1],$percent_download);
	$strDate = sprintf "%s", ($users[$i][$CONST_LCONNECTION]);

	#PRINT ON STDOUT
	printf "%s\t|\t%s\t", ($strLogin, $strUl);
	if ( length($strUl) < 8)
	{
		printf "\t";
	}
	printf "|\t%s\t", $strDl;
	if ( length($strDl) < 8)
	{
		printf "\t";
	}
	printf "|\t%s\n", $strDate;
	printf "\n";

	#PRINT SUMMARY FILE
	system ("echo -e '$users[$i][$CONST_USER] $users[$i][$CONST_TUPLOAD] $users[$i][$CONST_TDOWNLOAD] [$users[$i][$CONST_LCONNECTION]]' >> $CONST_SUMFILE");
}

#PREPARE BYTES, MBYTES OR GBYTES
@ftotal_upload = castSize $total_upload;
@ftotal_download = castSize $total_download;

#TABLE FOOTER
print "----------------------------------------------\n";
printf "*\t|\t%.2f %s\t|\t%.2f %s\n", ($ftotal_upload[0],$ftotal_upload[1],$ftotal_download[0],$ftotal_download[1]);
print "----------------------------------------------\n";

