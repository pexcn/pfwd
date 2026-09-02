# CLAUDE.md

**与我对话请用中文。**

## 语言

代码、注释、日志、提交信息用英文；

## 提交

遵循 Conventional Commits。

**AI 不代为提交。** 改完之后把写好的提交信息给我，由我自己执行 `git commit`；
不要运行 `git commit` / `git push`，也不要建分支。

**AI 参与的改动必须在信息末尾署名**，空一行后加 `Co-Authored-By` trailer，
谁改的署谁，多个模型接力就按参与顺序都列上：

```
Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
```

其他 AI 用各自的标识（如 `Codex <noreply@openai.com>`），别都挂在 Claude 名下。
署真正干活的**模型**，不是外壳工具 —— 在 Copilot 里用 BYOK 接的哪个模型就署哪个。
纯人工的提交不加这一行。

## 注释

**有必要才写，不是越密越好。**
