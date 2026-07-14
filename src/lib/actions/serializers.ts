/**
 * 导出序列化器
 *
 * 统一 CSV / JSON / Markdown 序列化，供 ExportMenu 与各面板复用。
 * 对齐 docs/UX-UI优化建议.md §6.1：导出默认当前筛选结果，文件名规范。
 */

export type ExportFormat = 'csv' | 'json' | 'markdown' | 'text';

export type CellValue = string | number | boolean | null | undefined;

/** CSV 单元格转义：含 " , \r \n 时用 "..." 包裹，内部 " → ""（RFC 4180） */
function escapeCsvCell(value: string): string {
  if (/["\r\n,]/.test(value)) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

/** 二维数组 → CSV 字符串。每个单元格自动转义；null/undefined → 空串。 */
export function toCsv(rows: CellValue[][]): string {
  return rows
    .map((row) =>
      row
        .map((cell) => {
          if (cell == null) return '';
          if (typeof cell === 'boolean') return cell ? 'true' : 'false';
          return escapeCsvCell(String(cell));
        })
        .join(','),
    )
    .join('\n');
}

/** JSON 美化序列化（2 空格）。循环引用等异常降级为单行字符串。 */
export function toJson(data: unknown): string {
  try {
    return JSON.stringify(data, null, 2);
  } catch {
    return JSON.stringify(String(data));
  }
}

/** Markdown 表格。表头与数据行的 `|` 与换行转义。 */
export function toMarkdownTable(headers: string[], rows: CellValue[][]): string {
  const esc = (v: string) => v.replace(/\|/g, '\\|').replace(/\n/g, ' ');
  const head = `| ${headers.map((h) => esc(h)).join(' | ')} |`;
  const sep = `| ${headers.map(() => '---').join(' | ')} |`;
  const body = rows
    .map(
      (row) =>
        `| ${row
          .map((cell) => {
            if (cell == null) return '';
            if (typeof cell === 'boolean') return cell ? 'true' : 'false';
            return esc(String(cell));
          })
          .join(' | ')} |`,
    )
    .join('\n');
  return `${head}\n${sep}\n${body}`;
}
