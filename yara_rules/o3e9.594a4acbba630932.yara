
rule o3e9_594a4acbba630932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.594a4acbba630932"
     cluster="o3e9.594a4acbba630932"
     cluster_size="7"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply bundler bgsaf"
     md5_hashes="['1171d99993344c5838eb64dd27250def','46acbaeceb50825b4a0ff418a1f9411d','dc8b7c66ca3e1f1a315a4d05bbcdbb95']"

   strings:
      $hex_string = { 72002000270025007300270020006e006f007400200066006f0075006e006400050041007000720069006c0003004d006100790004004a0075006e0065000400 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
