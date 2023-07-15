
rule n3e9_111a948dc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.111a948dc6220b12"
     cluster="n3e9.111a948dc6220b12"
     cluster_size="14"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dinwod razy trojandropper"
     md5_hashes="['287757a61089cc321f288c5b6bae6390','4fd7eeeab7631f8cf25a815285c1c08d','e9ea14f6765183ee77188dac05ddf5e6']"

   strings:
      $hex_string = { 07f05e2e76d3bab2a638d08ecf74c1581a2acb948a7f596d7b538fc3ed25c39d9effdf7e1528aa835f69f9bd854f4342d8894a12dd3ee363c5a9fe3aa772b468 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
