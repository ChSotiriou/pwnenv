local default_opts = { noremap = true, silent = true }

------------------------------------------------------------------

-- LSP
vim.api.nvim_set_keymap('n', 'gd', '<cmd>lua vim.lsp.buf.definition()<CR>', default_opts)
vim.api.nvim_set_keymap('n', 'gD', '<cmd>lua vim.lsp.buf.declaration()<CR>', default_opts)
vim.api.nvim_set_keymap('n', 'gr', '<cmd>lua vim.lsp.buf.references()<CR>', default_opts)
vim.api.nvim_set_keymap('n', 'gi', '<cmd>lua vim.lsp.buf.implementation()<CR>', default_opts)
vim.api.nvim_set_keymap('n', 'K', '<cmd>lua vim.lsp.buf.hover()<CR>', default_opts)
vim.api.nvim_set_keymap('n', '<C-k>', '<cmd>lua vim.lsp.buf.signature_help()<CR>', default_opts)
vim.api.nvim_set_keymap('n', '<C-n>', '<cmd>lua vim.lsp.diagnostic.goto_prev()<CR>', default_opts)
vim.api.nvim_set_keymap('n', '<C-p>', '<cmd>lua vim.lsp.diagnostic.goto_next()<CR>', default_opts)

------------------------------------------------------------------

-- telescope
vim.api.nvim_set_keymap('n', '<leader>ff', '<cmd>Telescope find_files<cr>', default_opts)
vim.api.nvim_set_keymap('n', '<leader>fg', '<cmd>Telescope live_grep<cr>', default_opts)
vim.api.nvim_set_keymap('n', '<leader>fb', '<cmd>Telescope buffers<cr>', default_opts)
vim.api.nvim_set_keymap('n', '<leader>fs', '<cmd>Telescope lsp_workspace_symbols<cr>', default_opts)
vim.api.nvim_set_keymap('n', '<leader>fd', '<cmd>Telescope diagnostics<cr>', default_opts)
vim.api.nvim_set_keymap('n', '<leader>fh', '<cmd>Telescope help_tags<cr>', default_opts)

------------------------------------------------------------------

-- vim commentary
vim.api.nvim_set_keymap('', '<leader>/', ':Commentary<CR>', {})

------------------------------------------------------------------

-- Vimspector
vim.api.nvim_set_keymap('n', '<leader>dl', ':call vimspector#Launch()<CR>', default_opts)
vim.api.nvim_set_keymap('n', '<leader>dr', ':VimspectorReset<CR>', default_opts)

vim.api.nvim_set_keymap('n', '<leader>db', ':call vimspector#ToggleBreakpoint()<CR>', default_opts)

------------------------------------------------------------------

-- Compile Commands
vim.api.nvim_set_keymap('n', '<F5>', ':w! <bar> !compile % `pwd`<CR><CR>', default_opts)
vim.api.nvim_set_keymap('n', '<leader><F5>', ':!openOutput %<CR><CR>', default_opts)

------------------------------------------------------------------

-- Vimsnippets
vim.g.UltiSnipsExpandTrigger = "<tab>"
vim.g.UltiSnipsJumpForwardTrigger = "<c-j>"
vim.g.UltiSnipsJumpBackwardTrigger = "<c-k>"

------------------------------------------------------------------

-- ToggleTerm
vim.api.nvim_set_keymap('', '<C-t>', ':ToggleTerm<CR>', {})

------------------------------------------------------------------

-- General Mappings
-- Map Y to act like D and C, i.e. to yank until EOL, rather than act as yy,
-- which is the default
vim.api.nvim_set_keymap('', 'Y', 'y$', {})

-- Copy-Paste to system cliboard
vim.api.nvim_set_keymap('v', '<C-y>', '"*y :let @+=@*<CR>', default_opts)
vim.api.nvim_set_keymap('', '<C-p>', '"+P', {})

-- Map <C-L> (redraw screen) to also turn off search highlighting until the
-- next search
vim.api.nvim_set_keymap('n', '<C-c>', ':nohl<CR><C-L>', default_opts)

-- Spell Checker
vim.api.nvim_set_keymap('', '<leader><F6>', ':setlocal spell!<CR>', {})

-- Change Language
vim.api.nvim_set_keymap('n', '<F6>', ':lua ChangeLanguage()<CR>', {})
vim.api.nvim_set_keymap('i', '<F6>', '<ESC>:lua ChangeLanguage()<CR>i', {})

-- Goyo
vim.api.nvim_set_keymap('', '<F10>', ':Goyo<CR>', {})

-- screen splits
vim.api.nvim_set_keymap('n', '<leader>h', ':split<CR>', default_opts)
vim.api.nvim_set_keymap('n', '<leader>v', ':vsplit<CR>', default_opts)

vim.api.nvim_set_keymap('n', '<C-s>', ':w<CR>', default_opts)
vim.api.nvim_set_keymap('n', '<C-q>', ':q<CR>', default_opts)

-- navigate splits
vim.api.nvim_set_keymap('', '<C-h>', '<C-w>h', default_opts)
vim.api.nvim_set_keymap('', '<C-j>', '<C-w>j', default_opts)
vim.api.nvim_set_keymap('', '<C-k>', '<C-w>k', default_opts)
vim.api.nvim_set_keymap('', '<C-l>', '<C-w>l', default_opts)

-- split lines
vim.api.nvim_set_keymap('', 'Q', 'gq', default_opts)

------------------------------------------------------------------
