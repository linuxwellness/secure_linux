import "hash"

rule k3e9_63146da1188a6b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63146da1188a6b16"
     cluster="k3e9.63146da1188a6b16"
     cluster_size="22 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['a655601b7399aefba6c7fa5ded7b873b', 'd51e9aaf558dff9ca68c6a401beac3e6', 'bcfb0f7c90e9e12cd7fde94d1470beed']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(28672,1024) == "cbe3f2c767bf3f871e1e15b0008153e1"
}

