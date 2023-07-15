import "hash"

rule k3e9_3c103ac9c8000b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3c103ac9c8000b14"
     cluster="k3e9.3c103ac9c8000b14"
     cluster_size="18 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="razy simbot backdoor"
     md5_hashes="['dc0be437b856f6a8dcd013917be18c51', 'dc0be437b856f6a8dcd013917be18c51', 'a4d44bc6e2f3406e42b7a830c1479c1d']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5632,1536) == "b09e1f7c28fc22c6f6859d92fabdae15"
}

