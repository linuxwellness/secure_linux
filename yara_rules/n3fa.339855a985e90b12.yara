import "hash"

rule n3fa_339855a985e90b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3fa.339855a985e90b12"
     cluster="n3fa.339855a985e90b12"
     cluster_size="550 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="malicious cloud high"
     md5_hashes="['e0bbf58c8e3dbfc7dc39af91b122db70', '604348965e7997df4cbc1f4651b282fd', 'b32cd2bed072ba46a665666f163adf58']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(655872,1024) == "cf317fe4eebe80b50487e7fc933c22d6"
}

