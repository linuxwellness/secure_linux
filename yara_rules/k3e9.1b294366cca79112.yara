import "hash"

rule k3e9_1b294366cca79112
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1b294366cca79112"
     cluster="k3e9.1b294366cca79112"
     cluster_size="3 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob malicious"
     md5_hashes="['4fce690644aa1f6cd6f2de64a93964e2', 'b5b106db30c6b7e19981c166d810e17e', '4fce690644aa1f6cd6f2de64a93964e2']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(12288,1024) == "0449c30b832c1c60111f03ffa49ccd7d"
}

