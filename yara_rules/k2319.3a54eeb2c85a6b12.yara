
rule k2319_3a54eeb2c85a6b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.3a54eeb2c85a6b12"
     cluster="k2319.3a54eeb2c85a6b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script aknjt"
     md5_hashes="['f3e793d554670f7c39587afc74b9a5e74bb93ff0','4c55bf017eca33e5121c17d3e282cd3079451ceb','65e3dd6268280c2a394d32debd22f0c228843b15']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.3a54eeb2c85a6b12"

   strings:
      $hex_string = { 4a5d213d3d756e646566696e6564297b72657475726e206f5b4a5d3b7d76617220723d282835392e2c39382e304531293e3d28307831372c38362e344531293f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
