function(nexus_apply_sanitizers target_name)
  if(NEXUS_ENABLE_ASAN)
    target_compile_options(${target_name} PRIVATE -fsanitize=address)
    target_link_options(${target_name} PRIVATE -fsanitize=address)
  endif()

  if(NEXUS_ENABLE_UBSAN)
    target_compile_options(${target_name} PRIVATE -fsanitize=undefined)
    target_link_options(${target_name} PRIVATE -fsanitize=undefined)
  endif()
endfunction()

