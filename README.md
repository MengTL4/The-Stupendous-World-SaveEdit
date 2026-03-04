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

- 工具不会自动改游戏资源文件，只处理你手动加载/导出的文本。

## useData内容解密
```python
python useData_tool.py batch-decode useData useData_decoded --overwrite
```
- 需要参数useData,代表游戏useData存放路径
- 需要useData_decoded,代表输出路径
- 其余参数可以默认

## data.pak内容解密
```python
python data_pak_tool.py batch-decode data.pak data_decoded_pycrypto --overwrite
```
- 需要参数data.pak,代表游戏data.pak文件位置
- 需要data_decoded_pycrypto,代表输出路径
- 其余参数可以默认