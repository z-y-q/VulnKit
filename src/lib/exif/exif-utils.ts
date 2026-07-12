// EXIF 解析工具 — 灵眸 v6.0
// 轻量级内联 EXIF/TIFF/GPS 解析，无外部依赖

// ---------- 类型 ----------

export interface ExifData {
  [key: string]: unknown;
}

export interface GpsCoordinate {
  decimal: number;
  dms: string;
}

export interface ExifSection {
  title: string;
  icon: string;
  fields: { label: string; value: string; raw: unknown }[];
}

// ---------- GPS 格式化 ----------

/** 将十进制度数转换为 DMS 字符串 (如 39°54'12.34"N) */
export function formatGpsDms(decimal: number, isLat: boolean): string {
  const abs = Math.abs(decimal);
  const d = Math.floor(abs);
  const m = Math.floor((abs - d) * 60);
  const s = ((abs - d) * 60 - m) * 60;
  const posDir = isLat ? 'N' : 'E';
  const negDir = isLat ? 'S' : 'W';
  const dir = decimal >= 0 ? posDir : negDir;
  return `${d}°${m}'${s.toFixed(2)}"${dir}`;
}

/** 构建 Google Maps URL */
export function buildMapUrl(lat: number, lng: number): string {
  return `https://www.google.com/maps?q=${lat},${lng}`;
}

// ---------- EXIF 字段格式化 ----------

export function formatExifValue(value: unknown, format?: string): string | null {
  if (value === undefined || value === null) return null;
  switch (format) {
    case 'date':
      if (value instanceof Date) return value.toLocaleString('zh-CN');
      return String(value);
    case 'fnumber':
      return `f/${value}`;
    case 'exposure': {
      const v = Number(value);
      if (v < 1) {
        const denom = Math.round(1 / v);
        return `1/${denom}s`;
      }
      return `${v}s`;
    }
    case 'ev':
      return `${Number(value) >= 0 ? '+' : ''}${value} EV`;
    case 'focal':
      return `${value}mm`;
    case 'pixel':
      return `${value} px`;
    case 'altitude':
      return `${value} m`;
    case 'metering': {
      const map: Record<number, string> = { 0: '未知', 1: '平均测光', 2: '中央重点', 3: '点测光', 4: '多点测光', 5: '矩阵测光', 6: '局部测光' };
      return map[Number(value)] || String(value);
    }
    case 'whitebalance':
      return Number(value) === 0 ? '手动' : Number(value) === 1 ? '自动' : String(value);
    case 'flash': {
      const v = Number(value);
      if (v === 0) return '未闪光';
      if (v === 1) return '已闪光';
      if (v === 16) return '关闭闪光';
      if (v === 24 || v === 25) return '自动未闪光';
      if (v === 28 || v === 29) return '自动已闪光';
      return String(value);
    }
    case 'exposureprogram': {
      const map: Record<number, string> = { 0: '未定义', 1: '手动', 2: '程序自动', 3: '光圈优先', 4: '快门优先', 5: '景深优先', 6: '运动模式', 7: '人像模式', 8: '风景模式' };
      return map[Number(value)] || String(value);
    }
    default:
      return String(value);
  }
}

// ---------- 章节定义 ----------

interface FieldDef {
  key: string;
  label: string;
  format?: string;
}

const EXIF_SECTIONS: { title: string; icon: string; fields: FieldDef[] }[] = [
  {
    title: '拍摄信息',
    icon: '\u{1F4F8}',
    fields: [
      { key: 'DateTimeOriginal', label: '拍摄时间', format: 'date' },
      { key: 'ISO', label: 'ISO 感光度' },
      { key: 'FNumber', label: '光圈', format: 'fnumber' },
      { key: 'ExposureTime', label: '快门速度', format: 'exposure' },
      { key: 'ExposureCompensation', label: '曝光补偿', format: 'ev' },
      { key: 'FocalLength', label: '焦距', format: 'focal' },
      { key: 'FocalLengthIn35mmFormat', label: '等效焦距', format: 'focal' },
      { key: 'MeteringMode', label: '测光模式', format: 'metering' },
      { key: 'WhiteBalance', label: '白平衡', format: 'whitebalance' },
      { key: 'Flash', label: '闪光灯', format: 'flash' },
      { key: 'ExposureProgram', label: '曝光程序', format: 'exposureprogram' },
    ],
  },
  {
    title: '相机信息',
    icon: '\u{1F4F7}',
    fields: [
      { key: 'Make', label: '品牌' },
      { key: 'Model', label: '型号' },
      { key: 'LensModel', label: '镜头' },
      { key: 'LensMake', label: '镜头品牌' },
      { key: 'Software', label: '软件' },
      { key: 'ImageWidth', label: '图像宽度', format: 'pixel' },
      { key: 'ImageHeight', label: '图像高度', format: 'pixel' },
      { key: 'ColorSpace', label: '色彩空间' },
    ],
  },
  {
    title: 'GPS 信息',
    icon: '\u{1F4CD}',
    fields: [
      { key: 'latitude', label: '纬度', format: 'gps' },
      { key: 'longitude', label: '经度', format: 'gps' },
      { key: 'GPSAltitude', label: '海拔', format: 'altitude' },
    ],
  },
];

// ---------- 轻量 EXIF 解析器 ----------

/** 从 ArrayBuffer 中解析 EXIF 数据 */
export function parseExif(buffer: ArrayBuffer): ExifData {
  const view = new DataView(buffer);
  const result: ExifData = {};

  if (view.byteLength < 8) return result;

  // PNG：签名 89 50 4E 47 0D 0A 1A 0A，查找 eXIf chunk（PNG 1.5+）
  if (view.getUint32(0) === 0x89504e47 && view.getUint32(4) === 0x0d0a1a0a) {
    let offset = 8;
    while (offset + 8 < view.byteLength) {
      const len = view.getUint32(offset);
      const type = view.getUint32(offset + 4);
      // 'eXIf' = 0x65584966
      if (type === 0x65584966) {
        // eXIf chunk 数据起始于 offset+8，直接是 TIFF 数据（无 "Exif\0\0" 头）
        parseTiffDirect(view, offset + 8, result);
        break;
      }
      offset += 12 + len; // len + type(4) + data(len) + crc(4)
      if (type === 0x49454e44) break; // IEND
    }
    return result;
  }

  // TIFF 直接格式（魔数 II*\0 或 MM\0*）
  const bo16 = view.getUint16(0);
  if (bo16 === 0x4949 || bo16 === 0x4d4d) {
    parseTiffDirect(view, 0, result);
    return result;
  }

  // JPEG：检查 SOI marker 0xFFD8
  if (bo16 !== 0xffd8) return result; // 不支持的格式

  // 查找 APP1 marker (0xFFE1)
  let offset = 2;
  while (offset < view.byteLength - 4) {
    const marker = view.getUint16(offset);
    if (marker === 0xffe1) {
      const len = view.getUint16(offset + 2);
      parseApp1(view, offset + 4, len - 2, result);
      break;
    }
    if ((marker & 0xff00) !== 0xff00) break; // not a valid marker
    const segLen = view.getUint16(offset + 2);
    offset += 2 + segLen;
  }

  return result;
}

/** 直接从 TIFF 头偏移解析（用于 PNG eXIf chunk 和裸 TIFF） */
function parseTiffDirect(view: DataView, tiffOffset: number, result: ExifData): void {
  if (tiffOffset + 8 > view.byteLength) return;
  const bo = view.getUint16(tiffOffset);
  if (bo !== 0x4949 && bo !== 0x4d4d) return;
  const isLittle = bo === 0x4949;
  if (view.getUint16(tiffOffset + 2, isLittle) !== 42) return;
  const ifd0Offset = view.getUint32(tiffOffset + 4, isLittle);
  parseIfd(view, tiffOffset, tiffOffset + ifd0Offset, isLittle, result, 'ifd0');
  const exifIfdPtr = result['ExifIFDPointer'] as number | undefined;
  if (typeof exifIfdPtr === 'number' && exifIfdPtr > 0) {
    parseIfd(view, tiffOffset, tiffOffset + exifIfdPtr, isLittle, result, 'exif');
  }
  const gpsIfdPtr = result['GPSInfoIFDPointer'] as number | undefined;
  if (typeof gpsIfdPtr === 'number' && gpsIfdPtr > 0) {
    parseIfd(view, tiffOffset, tiffOffset + gpsIfdPtr, isLittle, result, 'gps');
  }
  resolveGps(result, isLittle);
}

function parseApp1(view: DataView, dataOffset: number, dataLen: number, result: ExifData): void {
  // 检查 "Exif\0\0" header
  if (dataLen < 6) return;
  const header = String.fromCharCode(
    view.getUint8(dataOffset),
    view.getUint8(dataOffset + 1),
    view.getUint8(dataOffset + 2),
    view.getUint8(dataOffset + 3),
  );
  if (header !== 'Exif') return;

  const tiffOffset = dataOffset + 6;
  if (tiffOffset + 8 > view.byteLength) return;

  const bo = view.getUint16(tiffOffset); // byte order: 0x4949=II(little), 0x4d4d=MM(big)
  const isLittle = bo === 0x4949;
  const magic42 = view.getUint16(tiffOffset + 2, isLittle);
  if (magic42 !== 0x002a) return;

  const ifd0Offset = view.getUint32(tiffOffset + 4, isLittle);
  parseIfd(view, tiffOffset, tiffOffset + ifd0Offset, isLittle, result, 'ifd0');

  // 查找 Exif Sub IFD
  const exifIfdPtr = result['ExifIFDPointer'] as number | undefined;
  if (typeof exifIfdPtr === 'number' && exifIfdPtr > 0) {
    parseIfd(view, tiffOffset, tiffOffset + exifIfdPtr, isLittle, result, 'exif');
  }

  // 查找 GPS IFD
  const gpsIfdPtr = result['GPSInfoIFDPointer'] as number | undefined;
  if (typeof gpsIfdPtr === 'number' && gpsIfdPtr > 0) {
    parseIfd(view, tiffOffset, tiffOffset + gpsIfdPtr, isLittle, result, 'gps');
  }

  // 解析 GPS 坐标
  resolveGps(result, isLittle);
}

function parseIfd(
  view: DataView,
  tiffBase: number,
  ifdOffset: number,
  isLittle: boolean,
  result: ExifData,
  _section: string,
): void {
  if (ifdOffset + 2 > view.byteLength) return;
  const entryCount = view.getUint16(ifdOffset, isLittle);

  for (let i = 0; i < entryCount; i++) {
    const entryOff = ifdOffset + 2 + i * 12;
    if (entryOff + 12 > view.byteLength) break;

    const tag = view.getUint16(entryOff, isLittle);
    const type = view.getUint16(entryOff + 2, isLittle);
    const count = view.getUint32(entryOff + 4, isLittle);
    const valueOffset = entryOff + 8;

    const tagName = EXIF_TAGS[tag] || gpsTags[tag] || `Tag_${tag}`;
    let value: unknown;

    const typeSize = IFD_TYPE_SIZES[type] || 1;
    const totalSize = count * typeSize;

    if (totalSize <= 4) {
      value = readValue(view, valueOffset, type, count, isLittle);
    } else {
      const ptr = view.getUint32(valueOffset, isLittle);
      const absPtr = tiffBase + ptr;
      if (absPtr + totalSize <= view.byteLength) {
        value = readValue(view, absPtr, type, count, isLittle);
      }
    }

    // 标准化已知标签
    if (tag === 0x0112) {
      result['Orientation'] = value;
    } else if (tag === 0x8769 || tag === 0x8825) {
      // ExifIFDPointer / GPSInfoIFDPointer: 存储但不作为显示字段
      if (tag === 0x8769) result['ExifIFDPointer'] = value as number;
      else result['GPSInfoIFDPointer'] = value as number;
    } else {
      result[tagName] = value;
    }
  }

  // 查找下一个 IFD（IFD1 for thumbnail — 跳过以节省时间）
}

function readValue(view: DataView, offset: number, type: number, count: number, isLittle: boolean): unknown {
  switch (type) {
    case 1: // BYTE
      return count === 1 ? view.getUint8(offset) : readArray(view, offset, count, isLittle, 1, false);
    case 2: // ASCII
      return readAscii(view, offset, count);
    case 3: // SHORT
      return count === 1 ? view.getUint16(offset, isLittle) : readArray(view, offset, count, isLittle, 2, false);
    case 4: // LONG
      return count === 1 ? view.getUint32(offset, isLittle) : readArray(view, offset, count, isLittle, 4, false);
    case 5: // RATIONAL (unsigned)
      if (count === 1) return readRational(view, offset, isLittle, false);
      return readArray(view, offset, count, isLittle, 8, false, true);
    case 7: // UNDEFINED
      return count === 1 ? view.getUint8(offset) : readArray(view, offset, count, isLittle, 1, false);
    case 9: // SLONG
      return count === 1 ? view.getInt32(offset, isLittle) : readArray(view, offset, count, isLittle, 4, true);
    case 10: // SRATIONAL
      if (count === 1) return readRational(view, offset, isLittle, true);
      return readArray(view, offset, count, isLittle, 8, true, true);
    default:
      return null;
  }
}

function readAscii(view: DataView, offset: number, count: number): string {
  let s = '';
  for (let i = 0; i < count; i++) {
    const b = view.getUint8(offset + i);
    if (b === 0) break;
    s += String.fromCharCode(b);
  }
  return s.trim();
}

function readRational(view: DataView, offset: number, isLittle: boolean, signed: boolean): number {
  const num = signed ? view.getInt32(offset, isLittle) : view.getUint32(offset, isLittle);
  const den = signed ? view.getInt32(offset + 4, isLittle) : view.getUint32(offset + 4, isLittle);
  return den === 0 ? 0 : num / den;
}

function readArray(
  view: DataView, offset: number, count: number, isLittle: boolean,
  elemSize: number, signed: boolean, rational?: boolean,
): unknown[] {
  const arr: unknown[] = [];
  for (let i = 0; i < count; i++) {
    const off = offset + i * elemSize;
    if (rational) {
      arr.push(readRational(view, off, isLittle, signed));
    } else if (elemSize === 1) {
      arr.push(signed ? view.getInt8(off) : view.getUint8(off));
    } else if (elemSize === 2) {
      arr.push(signed ? view.getInt16(off, isLittle) : view.getUint16(off, isLittle));
    } else if (elemSize === 4) {
      arr.push(signed ? view.getInt32(off, isLittle) : view.getUint32(off, isLittle));
    }
  }
  return arr;
}

// ---------- GPS 解析 ----------

function resolveGps(result: ExifData, _isLittle: boolean): void {
  const lat = result['GPSLatitude'] as number[] | undefined;
  const latRef = result['GPSLatitudeRef'] as string | undefined;
  const lng = result['GPSLongitude'] as number[] | undefined;
  const lngRef = result['GPSLongitudeRef'] as string | undefined;

  if (lat && lat.length === 3 && lng && lng.length === 3) {
    const decLat = toDecimalDegrees(lat, latRef === 'S');
    const decLng = toDecimalDegrees(lng, lngRef === 'W');
    result['latitude'] = decLat;
    result['longitude'] = decLng;
  }
}

function toDecimalDegrees(dms: number[], negate: boolean): number {
  const deg = dms[0] || 0;
  const min = dms[1] || 0;
  const sec = dms[2] || 0;
  const decimal = deg + min / 60 + sec / 3600;
  return negate ? -decimal : decimal;
}

// ---------- 分组渲染 ----------

/** 将 EXIF 数据分组为可渲染的章节 */
export function groupExifSections(data: ExifData): ExifSection[] {
  const sections: ExifSection[] = [];

  for (const sectionDef of EXIF_SECTIONS) {
    const fields: ExifSection['fields'] = [];
    for (const field of sectionDef.fields) {
      const raw = data[field.key];
      if (raw === undefined || raw === null) continue;

      if (field.format === 'gps') {
        const coord = Number(raw);
        const isLat = field.key === 'latitude';
        fields.push({
          label: field.label,
          value: `${formatGpsDms(coord, isLat)} (${coord.toFixed(6)})`,
          raw: coord,
        });
      } else {
        const formatted = formatExifValue(raw, field.format);
        if (formatted) {
          fields.push({ label: field.label, value: formatted, raw });
        }
      }
    }

    if (fields.length > 0) {
      sections.push({ title: sectionDef.title, icon: sectionDef.icon, fields });
    }
  }

  // 如果有任何字段未归类，添加“其他”部分
  const knownKeys = new Set(EXIF_SECTIONS.flatMap(s => s.fields.map(f => f.key)));
  knownKeys.add('ExifIFDPointer');
  knownKeys.add('GPSInfoIFDPointer');
  knownKeys.add('GPSLatitude');
  knownKeys.add('GPSLatitudeRef');
  knownKeys.add('GPSLongitude');
  knownKeys.add('GPSLongitudeRef');

  const otherEntries: ExifSection['fields'] = [];
  for (const key of Object.keys(data)) {
    if (!knownKeys.has(key)) {
      otherEntries.push({ label: key, value: String(data[key]), raw: data[key] });
    }
  }
  if (otherEntries.length > 0) {
    sections.push({ title: '其他信息', icon: '\u{1F4CB}', fields: otherEntries });
  }

  return sections;
}

// ---------- 隐私检测 ----------

/** 检查 EXIF 数据中是否包含 GPS 位置信息 */
export function hasGpsPrivacyRisk(data: ExifData): boolean {
  return data['latitude'] !== undefined && data['longitude'] !== undefined;
}

// ---------- 标签表 ----------

const IFD_TYPE_SIZES: Record<number, number> = {
  1: 1, // BYTE
  2: 1, // ASCII
  3: 2, // SHORT
  4: 4, // LONG
  5: 8, // RATIONAL
  7: 1, // UNDEFINED
  9: 4, // SLONG
  10: 8, // SRATIONAL
};

const EXIF_TAGS: Record<number, string> = {
  0x010e: 'ImageDescription',
  0x010f: 'Make',
  0x0110: 'Model',
  0x0112: 'Orientation',
  0x011a: 'XResolution',
  0x011b: 'YResolution',
  0x0128: 'ResolutionUnit',
  0x0131: 'Software',
  0x0132: 'DateTime',
  0x013b: 'Artist',
  0x8298: 'Copyright',
  0x8769: 'ExifIFDPointer',
  0x8825: 'GPSInfoIFDPointer',
  // EXIF sub-IFD
  0x829a: 'ExposureTime',
  0x829d: 'FNumber',
  0x8822: 'ExposureProgram',
  0x8827: 'ISO',
  0x9000: 'ExifVersion',
  0x9003: 'DateTimeOriginal',
  0x9004: 'DateTimeDigitized',
  0x9201: 'ShutterSpeedValue',
  0x9202: 'ApertureValue',
  0x9204: 'ExposureCompensation',
  0x9205: 'MaxApertureValue',
  0x9207: 'MeteringMode',
  0x9209: 'Flash',
  0x920a: 'FocalLength',
  0xa001: 'ColorSpace',
  0xa002: 'ImageWidth',
  0xa003: 'ImageHeight',
  0xa405: 'FocalLengthIn35mmFormat',
  0xa431: 'BodySerialNumber',
  0xa432: 'LensSpecification',
  0xa433: 'LensMake',
  0xa434: 'LensModel',
};

const gpsTags: Record<number, string> = {
  0x0001: 'GPSLatitudeRef',
  0x0002: 'GPSLatitude',
  0x0003: 'GPSLongitudeRef',
  0x0004: 'GPSLongitude',
  0x0005: 'GPSAltitudeRef',
  0x0006: 'GPSAltitude',
  0x0007: 'GPSTimeStamp',
  0x001c: 'GPSDateStamp',
};
