import "hash"

rule m3ed_31ea55969ee31112
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.31ea55969ee31112"
     cluster="m3ed.31ea55969ee31112"
     cluster_size="12 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bpchjo"
     md5_hashes="['8480806d535552253c27d7b3ba1524e1', '8480806d535552253c27d7b3ba1524e1', '8480806d535552253c27d7b3ba1524e1']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(53248,1024) == "2e1fd58e17e7ebd34f1ab92566daa558"
}

