import "hash"

rule m3ed_296fa11499eb1912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.296fa11499eb1912"
     cluster="m3ed.296fa11499eb1912"
     cluster_size="39 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['798d733fb316e3b81c3543b8fe54e87a', '7ba3537979f094160a3c489ed8f6af10', 'b544436f515d49ecf9a5780583a4ad63']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(91136,1098) == "6328c395671af3d442197f887ae83fcf"
}

