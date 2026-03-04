# Save Web Tool (Vite + TypeScript)

RPG Maker 存档加解密网页工具，支持大体积 JSON 编辑。

## 功能

- 解密：`base64 -> zlib -> MessagePack -> JSON`
- 加密：JSON 回写为存档文本
- 树形 JSON 编辑（可逐节点展开/收缩）
- 支持标记类型往返：
  - `$binary`
  - `$ext`
  - `$map`
  - `$bigint`
- 可选保留源存档前后缀（例如 `1#SR|...`）

## 运行

```bash
npm install
npm run dev
```

构建：

```bash
npm run build
```

## 说明

- 工具位于独立目录：`save-web-tool/`
- 工具不会自动改游戏资源文件，只处理你手动加载/导出的文本。
