import "hash"

rule n3ed_31a45ec148001132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.31a45ec148001132"
     cluster="n3ed.31a45ec148001132"
     cluster_size="220 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['00644996b2565dab87af48991bea79f5', '866f19bb46dedb4195bf1ab94f8b3fce', 'b8c4cff31e80eeea9f18d73268744145']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(185344,1024) == "fe0380eba02c5234e3a403b108588d1d"
}

