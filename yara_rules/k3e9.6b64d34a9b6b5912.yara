import "hash"

rule k3e9_6b64d34a9b6b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34a9b6b5912"
     cluster="k3e9.6b64d34a9b6b5912"
     cluster_size="12 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['b2e15527f4fc733bbf06633db81ca977', 'a5b6995f84d5af2b45b7d312d54f575a', 'd2d95c5ccbd005ceffd0083ccff34bb7']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(12396,1036) == "647cd7f4094d87659d4644490060e83e"
}

