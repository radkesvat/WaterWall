# Preserve the pinned source cache. Saturated probe distances retain STC's
# two-byte metadata while keeping arbitrarily long collision chains searchable.
function(waterwall_stc_replace file before after)
  file(READ "${file}" content)
  string(FIND "${content}" "${before}" found)
  if(found EQUAL -1)
    message(FATAL_ERROR "WaterWall STC patch no longer matches ${file}")
  endif()
  string(REPLACE "${before}" "${after}" content "${content}")
  file(WRITE "${file}" "${content}")
endfunction()

function(waterwall_prepare_stc source_dir out_dir)
  set(destination "${CMAKE_BINARY_DIR}/patched-deps/stc")
  file(SHA256 "${CMAKE_CURRENT_FUNCTION_LIST_FILE}" recipe)
  set(stamp "bf1d20e3dd903cde66c301587e017c4dd234a620;${recipe}")
  set(previous "")
  if(EXISTS "${destination}/.waterwall-stamp")
    file(READ "${destination}/.waterwall-stamp" previous)
  endif()
  if(NOT stamp STREQUAL previous)
    file(REMOVE_RECURSE "${destination}")
    file(MAKE_DIRECTORY "${destination}")
    file(COPY "${source_dir}/include" DESTINATION "${destination}")
    waterwall_stc_replace("${destination}/include/stc/types.h"
      "uint16_t dist;" "size_t dist;")
    waterwall_stc_replace("${destination}/include/stc/hmap.h"
      "STC_DEF _m_result\n_c_MEMB(_bucket_lookup_)(const Self* self, const _m_keyraw* rkeyptr) {"
[=[/* Saturated metadata retains the exact Robin Hood ordering by recomputing
 * distance only for unusually long chains. Normal buckets keep the fast path. */
STC_INLINE size_t _c_MEMB(_bucket_distance_)(const Self* self, size_t index) {
    size_t distance = self->meta[index].dist;
    if (distance == _distmask) {
        const _m_keyraw raw = i_keytoraw(_i_keyref(&self->table[index]));
        const size_t mask = (size_t)self->bucket_count - 1;
        distance = ((index - (i_hash(&raw) & mask)) & mask) + 1;
    }
    return distance;
}

STC_DEF _m_result
_c_MEMB(_bucket_lookup_)(const Self* self, const _m_keyraw* rkeyptr) {]=])
    waterwall_stc_replace("${destination}/include/stc/hmap.h"
      "while (_res.dist <= self->meta[_res.idx].dist) {"
      "while (_res.dist <= _c_MEMB(_bucket_distance_)(self, _res.idx)) {")
    waterwall_stc_replace("${destination}/include/stc/hmap.h"
      ".dist=(uint16_t)(res.dist & _distmask)"
      ".dist=(uint16_t)((res.dist < _distmask ? res.dist : _distmask) & _distmask)")
    waterwall_stc_replace("${destination}/include/stc/hmap.h"
      "struct hmap_meta mcur = self->meta[res.idx];"
      "struct hmap_meta mcur = self->meta[res.idx];\n    size_t displaced_distance = _c_MEMB(_bucket_distance_)(self, res.idx);")
    waterwall_stc_replace("${destination}/include/stc/hmap.h"
      "            ++mcur.dist;"
      "            ++displaced_distance;\n            mcur.dist = (uint16_t)((displaced_distance < _distmask ? displaced_distance : _distmask) & _distmask);")
    waterwall_stc_replace("${destination}/include/stc/hmap.h"
      "            if (self->meta[res.idx].dist < mcur.dist) {"
      "            size_t current_distance = _c_MEMB(_bucket_distance_)(self, res.idx);\n            if (current_distance < displaced_distance) {\n                displaced_distance = current_distance;")
    waterwall_stc_replace("${destination}/include/stc/hmap.h"
[=[        if (m[j].dist < 2) // 0 => empty, 1 => PSL 0
            break;
        d[i] = d[j];
        m[i] = m[j];
        --m[i].dist;]=]
[=[        size_t distance = _c_MEMB(_bucket_distance_)(self, j);
        if (distance < 2) // 0 => empty, 1 => PSL 0
            break;
        d[i] = d[j];
        m[i] = m[j];
        --distance;
        m[i].dist = (uint16_t)((distance < _distmask ? distance : _distmask) & _distmask);]=])
    file(WRITE "${destination}/.waterwall-stamp" "${stamp}")
  endif()
  set(${out_dir} "${destination}" PARENT_SCOPE)
endfunction()
