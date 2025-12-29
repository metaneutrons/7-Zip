// 7zHandler.cpp

#include "StdAfx.h"

#include "../../../../C/CpuArch.h"
#include "../../../../C/Sha256.h"

#include "../../../Common/ComTry.h"
#include "../../../Common/IntToString.h"

#ifndef Z7_7Z_SET_PROPERTIES
#include "../../../Windows/System.h"
#endif

#include "../Common/ItemNameUtils.h"

#include "7zHandler.h"
#include "7zProperties.h"
#include "../../Crypto/7zSignature.h"

#ifdef Z7_7Z_SET_PROPERTIES
#ifdef Z7_EXTRACT_ONLY
#include "../Common/ParseProperties.h"
#endif
#endif

using namespace NWindows;
using namespace NCOM;

namespace NArchive {
namespace N7z {

CHandler::CHandler()
{
  _signatureVerifyResult = NExtract::NOperationResult::kOK;
  _signerWeakKey = false;
  _signerWeakAlgo = false;
  _sigVerifyLevel = NCrypto::NSigVerifyLevel::kStrict;
  
  #ifndef Z7_NO_CRYPTO
  _isEncrypted = false;
  _passwordIsDefined = false;
  #endif

  #ifdef Z7_EXTRACT_ONLY
  
  _crcSize = 4;
  
  #ifdef Z7_7Z_SET_PROPERTIES
  _useMultiThreadMixer = true;
  #endif
  
  #endif
}

Z7_COM7F_IMF(CHandler::GetNumberOfItems(UInt32 *numItems))
{
  *numItems = _db.Files.Size();
  return S_OK;
}

#ifdef Z7_SFX

IMP_IInArchive_ArcProps_NO_Table

Z7_COM7F_IMF(CHandler::GetNumberOfProperties(UInt32 *numProps))
{
  *numProps = 0;
  return S_OK;
}

Z7_COM7F_IMF(CHandler::GetPropertyInfo(UInt32 /* index */,
      BSTR * /* name */, PROPID * /* propID */, VARTYPE * /* varType */))
{
  return E_NOTIMPL;
}

#else

static const Byte kArcProps[] =
{
  kpidHeadersSize,
  kpidMethod,
  kpidSolid,
  kpidNumBlocks
  // , kpidIsTree
};

IMP_IInArchive_ArcProps

static inline char GetHex(unsigned value)
{
  return (char)((value < 10) ? ('0' + value) : ('A' + (value - 10)));
}

static unsigned ConvertMethodIdToString_Back(char *s, UInt64 id)
{
  int len = 0;
  do
  {
    s[--len] = GetHex((unsigned)id & 0xF); id >>= 4;
    s[--len] = GetHex((unsigned)id & 0xF); id >>= 4;
  }
  while (id != 0);
  return (unsigned)-len;
}

static void ConvertMethodIdToString(AString &res, UInt64 id)
{
  const unsigned kLen = 32;
  char s[kLen];
  unsigned len = kLen - 1;
  s[len] = 0;
  res += s + len - ConvertMethodIdToString_Back(s + len, id);
}


static char *GetStringForSizeValue(char *s, UInt32 val)
{
  for (unsigned i = 0; i < 32; i++)
    if (((UInt32)1 << i) == val)
    {
      if (i >= 10)
      {
        *s++= (char)('0' + i / 10);
        i %= 10;
      }
      *s++ = (char)('0' + i);
      *s = 0;
      return s;
    }
  
  char c = 'b';
  if      ((val & ((1 << 20) - 1)) == 0) { val >>= 20; c = 'm'; }
  else if ((val & ((1 << 10) - 1)) == 0) { val >>= 10; c = 'k'; }
  s = ConvertUInt32ToString(val, s);
  *s++ = c;
  *s = 0;
  return s;
}


static void GetLzma2String(char *s, unsigned d)
{
  if (d > 40)
  {
    *s = 0;
    return;
    // s = MyStpCpy(s, "unsup");
  }
  else if ((d & 1) == 0)
    d = (d >> 1) + 12;
  else
  {
    // s = GetStringForSizeValue(s, (UInt32)3 << ((d >> 1) + 11));
    d = (d >> 1) + 1;
    char c = 'k';
    if (d >= 10)
    {
      c = 'm';
      d -= 10;
    }
    s = ConvertUInt32ToString((UInt32)3 << d, s);
    *s++ = c;
    *s = 0;
    return;
  }
  ConvertUInt32ToString(d, s);
}


/*
static inline void AddHexToString(UString &res, Byte value)
{
  res += GetHex((Byte)(value >> 4));
  res += GetHex((Byte)(value & 0xF));
}
*/

static char *AddProp32(char *s, const char *name, UInt32 v)
{
  *s++ = ':';
  s = MyStpCpy(s, name);
  return ConvertUInt32ToString(v, s);
}
 
void CHandler::AddMethodName(AString &s, UInt64 id)
{
  AString name;
  FindMethod(EXTERNAL_CODECS_VARS id, name);
  if (name.IsEmpty())
    ConvertMethodIdToString(s, id);
  else
    s += name;
}

#endif

Z7_COM7F_IMF(CHandler::GetArchiveProperty(PROPID propID, PROPVARIANT *value))
{
  #ifndef Z7_SFX
  COM_TRY_BEGIN
  #endif
  NCOM::CPropVariant prop;
  switch (propID)
  {
    #ifndef Z7_SFX
    case kpidMethod:
    {
      AString s;
      const CParsedMethods &pm = _db.ParsedMethods;
      FOR_VECTOR (i, pm.IDs)
      {
        UInt64 id = pm.IDs[i];
        s.Add_Space_if_NotEmpty();
        char temp[16];
        if (id == k_LZMA2)
        {
          s += "LZMA2:";
          GetLzma2String(temp, pm.Lzma2Prop);
          s += temp;
        }
        else if (id == k_LZMA)
        {
          s += "LZMA:";
          GetStringForSizeValue(temp, pm.LzmaDic);
          s += temp;
        }
        /*
        else if (id == k_ZSTD)
        {
          s += "ZSTD";
        }
        */
        else
          AddMethodName(s, id);
      }
      prop = s;
      break;
    }
    case kpidSolid: prop = _db.IsSolid(); break;
    case kpidNumBlocks: prop = (UInt32)_db.NumFolders; break;
    case kpidHeadersSize:  prop = _db.HeadersSize; break;
    case kpidPhySize:  prop = _db.PhySize; break;
    case kpidOffset: if (_db.ArcInfo.StartPosition != 0) prop = _db.ArcInfo.StartPosition; break;
    /*
    case kpidIsTree: if (_db.IsTree) prop = true; break;
    case kpidIsAltStream: if (_db.ThereAreAltStreams) prop = true; break;
    case kpidIsAux: if (_db.IsTree) prop = true; break;
    */
    // case kpidError: if (_db.ThereIsHeaderError) prop = "Header error"; break;
    #endif
    
    case kpidWarningFlags:
    {
      UInt32 v = 0;
      if (_db.StartHeaderWasRecovered) v |= kpv_ErrorFlags_HeadersError;
      if (_db.UnsupportedFeatureWarning) v |= kpv_ErrorFlags_UnsupportedFeature;
      if (v != 0)
        prop = v;
      break;
    }
    
    case kpidWarning:
    {
      AString s;
      if (_signerWeakKey)
        s += "WARNING: Signing certificate uses weak key (Recommended: RSA 2048+)";
      if (_signerWeakAlgo)
      {
        if (!s.IsEmpty()) s += "\n";
        s += "WARNING: Weak legacy algorithm (SHA-1)";
      }
      if (!s.IsEmpty())
        prop = s;
      break;
    }
    
    case kpidErrorFlags:
    {
      UInt32 v = 0;
      if (!_db.IsArc) v |= kpv_ErrorFlags_IsNotArc;
      if (_db.ThereIsHeaderError) v |= kpv_ErrorFlags_HeadersError;
      if (_db.UnexpectedEnd) v |= kpv_ErrorFlags_UnexpectedEnd;
      // if (_db.UnsupportedVersion) v |= kpv_ErrorFlags_Unsupported;
      if (_db.UnsupportedFeatureError) v |= kpv_ErrorFlags_UnsupportedFeature;
      prop = v;
      break;
    }

    case kpidReadOnly:
    {
      if (!_db.CanUpdate())
        prop = true;
      break;
    }
    
    case kpidArchSignature:
    {
      if (_db.ArcInfo.ArchiveSignature.Size() > 0)
      {
        prop.SetBlob(_db.ArcInfo.ArchiveSignature, (ULONG)_db.ArcInfo.ArchiveSignature.Size());
      }
      break;
    }
    
    case kpidCertificateStore:
    {
      if (_db.ArcInfo.CertificateStore.Size() > 0)
      {
        prop.SetBlob(_db.ArcInfo.CertificateStore, (ULONG)_db.ArcInfo.CertificateStore.Size());
      }
      break;
    }
    
    case kpidSignerName:
    {
      if (!_signerName.IsEmpty())
        prop = _signerName;
      break;
    }
    
    case kpidSignatureStatus:
    {
      if (_db.ArcInfo.ArchiveSignature.Size() > 0)
        prop = (UInt32)_signatureVerifyResult;
      break;
    }
    
    case kpidSignerIssuer:
    {
      if (!_signerIssuer.IsEmpty())
        prop = _signerIssuer;
      break;
    }
    
    case kpidTimestampAuthority:
    {
      if (!_timestampAuthority.IsEmpty())
        prop = _timestampAuthority;
      break;
    }
    
    case kpidTimestampTime:
    {
      if (!_timestampTime.IsEmpty())
        prop = _timestampTime;
      break;
    }
    
    default: break;
  }
  return prop.Detach(value);
  #ifndef Z7_SFX
  COM_TRY_END
  #endif
}

static void SetFileTimeProp_From_UInt64Def(PROPVARIANT *prop, const CUInt64DefVector &v, unsigned index)
{
  UInt64 value;
  if (v.GetItem(index, value))
    PropVarEm_Set_FileTime64_Prec(prop, value, k_PropVar_TimePrec_100ns);
}

void CHandler::StoreCertInfo(const NCrypto::CCertInfo &certInfo)
{
  _signerName = certInfo.Subject;
  _signerIssuer = certInfo.Issuer;
  _signerWeakKey = certInfo.IsWeakKey;
  _signerWeakAlgo = certInfo.IsWeakAlgo;
  _signerExpired = certInfo.IsExpired;
  _hasTimestamp = certInfo.TimestampInfo.HasTimestamp;
  _timestampAuthority = certInfo.TimestampInfo.Authority;
  _timestampTime = certInfo.TimestampInfo.Timestamp;
}

bool CHandler::IsFolderEncrypted(CNum folderIndex) const
{
  if (folderIndex == kNumNoIndex)
    return false;
  const size_t startPos = _db.FoCodersDataOffset[folderIndex];
  const Byte *p = _db.CodersData.ConstData() + startPos;
  const size_t size = _db.FoCodersDataOffset[folderIndex + 1] - startPos;
  CInByte2 inByte;
  inByte.Init(p, size);
  
  CNum numCoders = inByte.ReadNum();
  for (; numCoders != 0; numCoders--)
  {
    const Byte mainByte = inByte.ReadByte();
    const unsigned idSize = (mainByte & 0xF);
    const Byte *longID = inByte.GetPtr();
    UInt64 id64 = 0;
    for (unsigned j = 0; j < idSize; j++)
      id64 = ((id64 << 8) | longID[j]);
    inByte.SkipDataNoCheck(idSize);
    if (id64 == k_AES)
      return true;
    if ((mainByte & 0x20) != 0)
      inByte.SkipDataNoCheck(inByte.ReadNum());
  }
  return false;
}

Z7_COM7F_IMF(CHandler::GetNumRawProps(UInt32 *numProps))
{
  *numProps = 0;
  return S_OK;
}

Z7_COM7F_IMF(CHandler::GetRawPropInfo(UInt32 /* index */, BSTR *name, PROPID *propID))
{
  *name = NULL;
  *propID = kpidNtSecure;
  return S_OK;
}

Z7_COM7F_IMF(CHandler::GetParent(UInt32 /* index */, UInt32 *parent, UInt32 *parentType))
{
  /*
  const CFileItem &file = _db.Files[index];
  *parentType = (file.IsAltStream ? NParentType::kAltStream : NParentType::kDir);
  *parent = (UInt32)(Int32)file.Parent;
  */
  *parentType = NParentType::kDir;
  *parent = (UInt32)(Int32)-1;
  return S_OK;
}

Z7_COM7F_IMF(CHandler::GetRawProp(UInt32 index, PROPID propID, const void **data, UInt32 *dataSize, UInt32 *propType))
{
  *data = NULL;
  *dataSize = 0;
  *propType = 0;

  if (/* _db.IsTree && propID == kpidName ||
      !_db.IsTree && */ propID == kpidPath)
  {
    if (_db.NameOffsets && _db.NamesBuf)
    {
      const size_t offset = _db.NameOffsets[index];
      const size_t size = (_db.NameOffsets[index + 1] - offset) * 2;
      if (size < ((UInt32)1 << 31))
      {
        *data = (const void *)(_db.NamesBuf.ConstData() + offset * 2);
        *dataSize = (UInt32)size;
        *propType = NPropDataType::kUtf16z;
      }
    }
    return S_OK;
  }
  /*
  if (propID == kpidNtSecure)
  {
    if (index < (UInt32)_db.SecureIDs.Size())
    {
      int id = _db.SecureIDs[index];
      size_t offs = _db.SecureOffsets[id];
      size_t size = _db.SecureOffsets[id + 1] - offs;
      if (size >= 0)
      {
        *data = _db.SecureBuf + offs;
        *dataSize = (UInt32)size;
        *propType = NPropDataType::kRaw;
      }
    }
  }
  */
  return S_OK;
}

#ifndef Z7_SFX

HRESULT CHandler::SetMethodToProp(CNum folderIndex, PROPVARIANT *prop) const
{
  PropVariant_Clear(prop);
  if (folderIndex == kNumNoIndex)
    return S_OK;
  // for (int ttt = 0; ttt < 1; ttt++) {
  const unsigned kTempSize = 256;
  char temp[kTempSize];
  unsigned pos = kTempSize;
  temp[--pos] = 0;
 
  const size_t startPos = _db.FoCodersDataOffset[folderIndex];
  const Byte *p = _db.CodersData.ConstData() + startPos;
  const size_t size = _db.FoCodersDataOffset[folderIndex + 1] - startPos;
  CInByte2 inByte;
  inByte.Init(p, size);
  
  // numCoders == 0 ???
  CNum numCoders = inByte.ReadNum();
  bool needSpace = false;
  
  for (; numCoders != 0; numCoders--, needSpace = true)
  {
    if (pos < 32) // max size of property
      break;
    const Byte mainByte = inByte.ReadByte();
    UInt64 id64 = 0;
    const unsigned idSize = (mainByte & 0xF);
    const Byte *longID = inByte.GetPtr();
    for (unsigned j = 0; j < idSize; j++)
      id64 = ((id64 << 8) | longID[j]);
    inByte.SkipDataNoCheck(idSize);

    if ((mainByte & 0x10) != 0)
    {
      inByte.ReadNum(); // NumInStreams
      inByte.ReadNum(); // NumOutStreams
    }
  
    CNum propsSize = 0;
    const Byte *props = NULL;
    if ((mainByte & 0x20) != 0)
    {
      propsSize = inByte.ReadNum();
      props = inByte.GetPtr();
      inByte.SkipDataNoCheck(propsSize);
    }
    
    const char *name = NULL;
    char s[32];
    s[0] = 0;
    
    if (id64 <= (UInt32)0xFFFFFFFF)
    {
      const UInt32 id = (UInt32)id64;
      if (id == k_LZMA)
      {
        name = "LZMA";
        if (propsSize == 5)
        {
          const UInt32 dicSize = GetUi32((const Byte *)props + 1);
          char *dest = GetStringForSizeValue(s, dicSize);
          UInt32 d = props[0];
          if (d != 0x5D)
          {
            const UInt32 lc = d % 9;
            d /= 9;
            const UInt32 pb = d / 5;
            const UInt32 lp = d % 5;
            if (lc != 3) dest = AddProp32(dest, "lc", lc);
            if (lp != 0) dest = AddProp32(dest, "lp", lp);
            if (pb != 2) dest = AddProp32(dest, "pb", pb);
          }
        }
      }
      else if (id == k_LZMA2)
      {
        name = "LZMA2";
        if (propsSize == 1)
          GetLzma2String(s, props[0]);
      }
      else if (id == k_PPMD)
      {
        name = "PPMD";
        if (propsSize == 5)
        {
          char *dest = s;
          *dest++ = 'o';
          dest = ConvertUInt32ToString(*props, dest);
          dest = MyStpCpy(dest, ":mem");
          GetStringForSizeValue(dest, GetUi32(props + 1));
        }
      }
      else if (id == k_Delta)
      {
        name = "Delta";
        if (propsSize == 1)
          ConvertUInt32ToString((UInt32)props[0] + 1, s);
      }
      else if (id == k_ARM64 || id == k_RISCV)
      {
        name = id == k_ARM64 ? "ARM64" : "RISCV";
        if (propsSize == 4)
          ConvertUInt32ToString(GetUi32(props), s);
        /*
        else if (propsSize != 0)
          MyStringCopy(s, "unsupported");
        */
      }
      else if (id == k_BCJ2) name = "BCJ2";
      else if (id == k_BCJ) name = "BCJ";
      else if (id == k_AES)
      {
        name = "7zAES";
        if (propsSize >= 1)
        {
          const Byte firstByte = props[0];
          const UInt32 numCyclesPower = firstByte & 0x3F;
          ConvertUInt32ToString(numCyclesPower, s);
        }
      }
    }
    
    if (name)
    {
      const unsigned nameLen = MyStringLen(name);
      const unsigned propsLen = MyStringLen(s);
      unsigned totalLen = nameLen + propsLen;
      if (propsLen != 0)
        totalLen++;
      if (needSpace)
        totalLen++;
      if (totalLen + 5 >= pos)
        break;
      pos -= totalLen;
      MyStringCopy(temp + pos, name);
      if (propsLen != 0)
      {
        char *dest = temp + pos + nameLen;
        *dest++ = ':';
        MyStringCopy(dest, s);
      }
      if (needSpace)
        temp[pos + totalLen - 1] = ' ';
    }
    else
    {
      AString methodName;
      FindMethod(EXTERNAL_CODECS_VARS id64, methodName);
      if (needSpace)
        temp[--pos] = ' ';
      if (methodName.IsEmpty())
        pos -= ConvertMethodIdToString_Back(temp + pos, id64);
      else
      {
        const unsigned len = methodName.Len();
        if (len + 5 > pos)
          break;
        pos -= len;
        for (unsigned i = 0; i < len; i++)
          temp[pos + i] = methodName[i];
      }
    }
  }
  
  if (numCoders != 0 && pos >= 4)
  {
    temp[--pos] = ' ';
    temp[--pos] = '.';
    temp[--pos] = '.';
    temp[--pos] = '.';
  }
  
  return PropVarEm_Set_Str(prop, temp + pos);
  // }
}

#endif

Z7_COM7F_IMF(CHandler::GetProperty(UInt32 index, PROPID propID, PROPVARIANT *value))
{
  RINOK(PropVariant_Clear(value))
  // COM_TRY_BEGIN
  // NCOM::CPropVariant prop;
  
  /*
  const CRef2 &ref2 = _refs[index];
  if (ref2.Refs.IsEmpty())
    return E_FAIL;
  const CRef &ref = ref2.Refs.Front();
  */
  
  const CFileItem &item = _db.Files[index];
  const UInt32 index2 = index;

  switch (propID)
  {
    case kpidIsDir: PropVarEm_Set_Bool(value, item.IsDir); break;
    case kpidSize:
    {
      PropVarEm_Set_UInt64(value, item.Size);
      // prop = ref2.Size;
      break;
    }
    case kpidPackSize:
    {
      // prop = ref2.PackSize;
      {
        const CNum folderIndex = _db.FileIndexToFolderIndexMap[index2];
        if (folderIndex != kNumNoIndex)
        {
          if (_db.FolderStartFileIndex[folderIndex] == (CNum)index2)
            PropVarEm_Set_UInt64(value, _db.GetFolderFullPackSize(folderIndex));
          /*
          else
            PropVarEm_Set_UInt64(value, 0);
          */
        }
        else
          PropVarEm_Set_UInt64(value, 0);
      }
      break;
    }
    // case kpidIsAux: prop = _db.IsItemAux(index2); break;
    case kpidPosition:  { UInt64 v; if (_db.StartPos.GetItem(index2, v)) PropVarEm_Set_UInt64(value, v); break; }
    case kpidCTime:  SetFileTimeProp_From_UInt64Def(value, _db.CTime, index2); break;
    case kpidATime:  SetFileTimeProp_From_UInt64Def(value, _db.ATime, index2); break;
    case kpidMTime:  SetFileTimeProp_From_UInt64Def(value, _db.MTime, index2); break;
    case kpidAttrib:  if (_db.Attrib.ValidAndDefined(index2)) PropVarEm_Set_UInt32(value, _db.Attrib.Vals[index2]); break;
    case kpidCRC:  if (item.CrcDefined) PropVarEm_Set_UInt32(value, item.Crc); break;
    case kpidEncrypted:  PropVarEm_Set_Bool(value, IsFolderEncrypted(_db.FileIndexToFolderIndexMap[index2])); break;
    case kpidIsAnti:  PropVarEm_Set_Bool(value, _db.IsItemAnti(index2)); break;
    /*
    case kpidIsAltStream:  prop = item.IsAltStream; break;
    case kpidNtSecure:
      {
        int id = _db.SecureIDs[index];
        size_t offs = _db.SecureOffsets[id];
        size_t size = _db.SecureOffsets[id + 1] - offs;
        if (size >= 0)
        {
          prop.SetBlob(_db.SecureBuf + offs, (ULONG)size);
        }
        break;
      }
    */

    case kpidPath: return _db.GetPath_Prop(index, value);
    
    case kpidFileSignature:
      if (index < _db.FileSignatures.Size() && _db.FileSignatures[index].Size() > 0)
      {
        const CByteBuffer &sig = _db.FileSignatures[index];
        NCOM::CPropVariant prop;
        prop.SetBlob(sig, (ULONG)sig.Size());
        return prop.Detach(value);
      }
      break;
    
    #ifndef Z7_SFX
    
    case kpidMethod: return SetMethodToProp(_db.FileIndexToFolderIndexMap[index2], value);
    case kpidBlock:
      {
        const CNum folderIndex = _db.FileIndexToFolderIndexMap[index2];
        if (folderIndex != kNumNoIndex)
          PropVarEm_Set_UInt32(value, (UInt32)folderIndex);
      }
      break;
   #ifdef Z7_7Z_SHOW_PACK_STREAMS_SIZES
    case kpidPackedSize0:
    case kpidPackedSize1:
    case kpidPackedSize2:
    case kpidPackedSize3:
    case kpidPackedSize4:
      {
        const CNum folderIndex = _db.FileIndexToFolderIndexMap[index2];
        if (folderIndex != kNumNoIndex)
        {
          if (_db.FolderStartFileIndex[folderIndex] == (CNum)index2 &&
              _db.FoStartPackStreamIndex[folderIndex + 1] -
              _db.FoStartPackStreamIndex[folderIndex] > (propID - kpidPackedSize0))
          {
            PropVarEm_Set_UInt64(value, _db.GetFolderPackStreamSize(folderIndex, propID - kpidPackedSize0));
          }
        }
        else
          PropVarEm_Set_UInt64(value, 0);
      }
      break;
   #endif
    
    #endif
    default: break;
  }
  // return prop.Detach(value);
  return S_OK;
  // COM_TRY_END
}

Z7_COM7F_IMF(CHandler::Open(IInStream *stream,
    const UInt64 *maxCheckStartPosition,
    IArchiveOpenCallback *openArchiveCallback))
{
  COM_TRY_BEGIN
  Close();
  #ifndef Z7_SFX
  _fileInfoPopIDs.Clear();
  #endif
  
  try
  {
    CMyComPtr<IArchiveOpenCallback> openArchiveCallbackTemp = openArchiveCallback;

    #ifndef Z7_NO_CRYPTO
    CMyComPtr<ICryptoGetTextPassword> getTextPassword;
    if (openArchiveCallback)
      openArchiveCallbackTemp.QueryInterface(IID_ICryptoGetTextPassword, &getTextPassword);
    #endif

    CInArchive archive(
          #ifdef Z7_7Z_SET_PROPERTIES
          _useMultiThreadMixer
          #else
          true
          #endif
          );
    _db.IsArc = false;
    RINOK(archive.Open(stream, maxCheckStartPosition))
    _db.IsArc = true;
    
    HRESULT result = archive.ReadDatabase(
        EXTERNAL_CODECS_VARS
        _db
        #ifndef Z7_NO_CRYPTO
          , getTextPassword, _isEncrypted, _passwordIsDefined, _password
        #endif
        );
    RINOK(result)
    
    // Verify archive signature if present
    _signatureVerifyResult = NExtract::NOperationResult::kOK;
    if (_db.ArcInfo.ArchiveSignature.Size() > 0)
    {
      try {
        // Compute hash of header content for signature verification
        // NOTE: This hash computation MUST match the one in 7zUpdate.cpp for signing
        CSha256 sha;
        Sha256_Init(&sha);
        
        // Hash pack sizes
        for (CNum i = 0; i < _db.NumPackStreams; i++)
        {
          UInt64 size = _db.GetStreamPackSize(i);
          Sha256_Update(&sha, (const Byte *)&size, sizeof(size));
        }
        
        // Hash file count
        UInt32 numFiles = _db.Files.Size();
        Sha256_Update(&sha, (const Byte *)&numFiles, sizeof(numFiles));
        
        // Hash file metadata
        for (unsigned i = 0; i < _db.Files.Size(); i++)
        {
          const CFileItem &file = _db.Files[i];
          Sha256_Update(&sha, (const Byte *)&file.Size, sizeof(file.Size));
          Sha256_Update(&sha, (const Byte *)&file.Crc, sizeof(file.Crc));
          Byte flags = (file.HasStream ? 1 : 0) | (file.IsDir ? 2 : 0) | (file.CrcDefined ? 4 : 0);
          Sha256_Update(&sha, &flags, 1);
          
          // Hash filename
          if (_db.NameOffsets && i < _db.Files.Size())
          {
            size_t nameOffset = _db.NameOffsets[i];
            size_t nameLen = _db.NameOffsets[i + 1] - nameOffset;
            const Byte *nameData = _db.NamesBuf.ConstData() + nameOffset * 2;
            Sha256_Update(&sha, nameData, nameLen * 2);
          }
        }
        
        // Hash timestamps if present
        for (unsigned i = 0; i < _db.MTime.Vals.Size(); i++)
        {
          UInt64 mtime = _db.MTime.Vals[i];
          Sha256_Update(&sha, (const Byte *)&mtime, sizeof(mtime));
        }
        
        // Hash attributes if present
        for (unsigned i = 0; i < _db.Attrib.Vals.Size(); i++)
        {
          UInt32 attr = _db.Attrib.Vals[i];
          Sha256_Update(&sha, (const Byte *)&attr, sizeof(attr));
        }
        
        // Include file signatures for cryptographic binding (must match signing)
        for (unsigned i = 0; i < _db.FileSignatures.Size(); i++)
        {
          if (_db.FileSignatures[i].Size() > 0)
            Sha256_Update(&sha, _db.FileSignatures[i], _db.FileSignatures[i].Size());
        }
        
        Byte digest[SHA256_DIGEST_SIZE];
        Sha256_Final(&sha, digest);
        
        NCrypto::CSignatureHandler sigHandler;
        if (!_trustStorePath.IsEmpty())
          sigHandler.SetTrustStore(_trustStorePath);
        NCrypto::CCertInfo certInfo;
        sigHandler.Verify(digest, SHA256_DIGEST_SIZE, 
                          _db.ArcInfo.ArchiveSignature,
                          _db.ArcInfo.ArchiveSignature.Size(),
                          _signatureVerifyResult, certInfo);
        StoreCertInfo(certInfo);
        
        // Extract certificate store for detailed parsing
        sigHandler.GetCertificateChain(_db.ArcInfo.CertificateStore);
      }
      catch (...) {
        // Signature verification failed, but don't fail the archive open
        _signatureVerifyResult = NExtract::NOperationResult::kSignatureFailed;
      }
    }
    
    // Extract certificate info from file signatures if no archive signature
    if (_db.ArcInfo.ArchiveSignature.Size() == 0 && _db.FileSignatures.Size() > 0)
    {
      // Find first non-empty file signature and extract certificate
      for (unsigned i = 0; i < _db.FileSignatures.Size(); i++)
      {
        if (_db.FileSignatures[i].Size() > 0)
        {
          try {
            NCrypto::CSignatureHandler sigHandler;
            if (!_trustStorePath.IsEmpty())
              sigHandler.SetTrustStore(_trustStorePath);
            NCrypto::CCertInfo certInfo;
            
            // Verify signature to extract certificate info (we don't need the data hash for this)
            Byte dummyHash[32] = {0};
            Int32 verifyResult;
            sigHandler.Verify(dummyHash, 32,
                              _db.FileSignatures[i],
                              _db.FileSignatures[i].Size(),
                              verifyResult, certInfo);
            
            // Store certificate info even if verification fails
            StoreCertInfo(certInfo);
            
            // Extract certificate store for detailed parsing
            sigHandler.GetCertificateChain(_db.ArcInfo.CertificateStore);
            break; // Use first signature found
          }
          catch (...) {
            // Continue to next signature if this one fails
          }
        }
      }
    }
    
    _inStream = stream;
  }
  catch(...)
  {
    Close();
    // return E_INVALIDARG;
    // return S_FALSE;
    // we must return out_of_memory here
    return E_OUTOFMEMORY;
  }
  // _inStream = stream;
  #ifndef Z7_SFX
  FillPopIDs();
  #endif
  return S_OK;
  COM_TRY_END
}

Z7_COM7F_IMF(CHandler::Close())
{
  COM_TRY_BEGIN
  _inStream.Release();
  _db.Clear();
  #ifndef Z7_NO_CRYPTO
  _isEncrypted = false;
  _passwordIsDefined = false;
  _password.Wipe_and_Empty();
  #endif
  return S_OK;
  COM_TRY_END
}

#ifdef Z7_7Z_SET_PROPERTIES
#ifdef Z7_EXTRACT_ONLY

Z7_COM7F_IMF(CHandler::SetProperties(const wchar_t * const *names, const PROPVARIANT *values, UInt32 numProps))
{
  COM_TRY_BEGIN
  
  InitCommon();
  _useMultiThreadMixer = true;

  for (UInt32 i = 0; i < numProps; i++)
  {
    UString name = names[i];
    name.MakeLower_Ascii();
    if (name.IsEmpty())
      return E_INVALIDARG;
    const PROPVARIANT &value = values[i];
    
    // Digital signature trust store
    if (name.IsEqualTo("dst"))
    {
      if (value.vt == VT_BSTR)
        _trustStorePath = value.bstrVal;
      continue;
    }
    
    // Digital signature verification level
    if (name.IsEqualTo("dsv"))
    {
      if (value.vt == VT_UI4)
        _sigVerifyLevel = (NCrypto::NSigVerifyLevel::EEnum)value.ulVal;
      else if (value.vt == VT_BSTR && value.bstrVal && value.bstrVal[0])
        _sigVerifyLevel = (NCrypto::NSigVerifyLevel::EEnum)(value.bstrVal[0] - '0');
      continue;
    }
    
    UInt32 number;
    const unsigned index = ParseStringToUInt32(name, number);
    if (index == 0)
    {
      if (name.IsEqualTo("mtf"))
      {
        RINOK(PROPVARIANT_to_bool(value, _useMultiThreadMixer))
        continue;
      }
      {
        HRESULT hres;
        if (SetCommonProperty(name, value, hres))
        {
          RINOK(hres)
          continue;
        }
      }
      return E_INVALIDARG;
    }
  }
  return S_OK;
  COM_TRY_END
}

#endif
#endif

IMPL_ISetCompressCodecsInfo

}}
