*** Begin Patch
*** Update File: src/CMakeLists.txt
@@
  # existing content...
 
+# Add blockstorage subdir (contains in-memory backend used by unit tests)
+add_subdirectory(blockstorage)
+
*** End Patch
