-------------------------------------------------------------------------------

-- Vim with default settings does not allow easy switching between multiple files
-- in the same editor window. Users can use multiple split windows or multiple
-- tab pages to edit multiple files, but it is still best to enable an option to
-- allow easier switching between files.
--
-- One such option is the 'hidden' option, which allows you to re-use the same
-- window and switch from an unsaved buffer without saving it first. Also allows
-- you to keep an undo history for multiple files when re-using the same window
-- in this way. Note that using persistent undo also lets you undo in multiple
-- files even in the same window, but is less efficient and is actually designed
-- for keeping undo history after closing Vim entirely. Vim will complain if you
-- try to quit without saving, and swap files will keep you safe if your computer " crashes.
vim.api.nvim_set_option('hidden', true)

-- Note that not everyone likes working this way (with the hidden option).
-- Alternatives include using tabs or split windows instead of re-using the same
-- window as mentioned above, and/or either of the following options:
-- set confirm
-- set autowriteall

-- Better command-line completion
vim.api.nvim_set_option('wildmenu', true)

-- Show partial commands in the last line of the screen
vim.api.nvim_set_option('showcmd', true)

-- Modelines have historically been a source of security vulnerabilities. As
-- such, it may be a good idea to disable them and use the securemodelines
-- script, <http://www.vim.org/scripts/script.php?script_id=1876>.
-- set nomodeline

-- Turn on syntax highlighting
vim.cmd('syntax on')

-- highlighting on search
vim.api.nvim_set_option('hlsearch', true)

-- center screen in insert mode
vim.cmd('autocmd InsertEnter * norm zz')

-- Automatically deletes all trailing whitespace and newlines at end of file on save.
vim.cmd([[
    autocmd BufWritePre * %s/\s\+$//e
    autocmd BufWritePre * %s/\n\+\%$//e
    autocmd BufWritePre *.[ch] %s/\%$/\r/e
]])

-- Prevent VIM from erasing clipboard at exit
vim.cmd([[
    autocmd VimLeave * call system("xsel -ib", getreg('+'))
]])

vim.api.nvim_set_option('backup', false)

-------------------------------------------------------------------------------

-- Usability options
--
-- These are options that users frequently set in their .vimrc. Some of them
-- change Vim's behaviour in ways which deviate from the true Vi way, but
-- which are considered to add usability. Which, if any, of these options to
-- use is very much a personal preference, but they are harmless.

-- Use case insensitive search, except when using capital letters
vim.api.nvim_set_option('ignorecase', true)
vim.api.nvim_set_option('smartcase', true)

-- Allow backspacing over autoindent, line breaks and start of insert action
vim.api.nvim_set_option('backspace', 'indent,eol,start')

-- When opening a new line and no filetype-specific indenting is enabled, keep
-- the same indent as the line you're currently on. Useful for READMEs, etc.
vim.api.nvim_set_option('autoindent', true)

-- Stop certain movements from always going to the first character of a line.
-- While this behaviour deviates from that of Vi, it does what most users
-- coming from other editors would expect.
vim.api.nvim_set_option('startofline', false)

-- Display the cursor position on the last line of the screen or in the status
-- line of a window
vim.api.nvim_set_option('ruler', true)

-- Always display the status line, even if only one window is displayed
vim.api.nvim_set_option('laststatus', 2)

-- Instead of failing a command because of unsaved changes, instead raise a
-- dialogue asking if you wish to save changed files.
vim.api.nvim_set_option('confirm', true)

-- Use visual bell instead of beeping when doing something wrong
vim.api.nvim_set_option('visualbell', true)

-- And reset the terminal code for the visual bell. If visualbell is set, and
-- this line is also included, vim will neither flash nor beep. If visualbell
-- is unset, this does nothing.
vim.api.nvim_set_option('t_vb', '')

-- Enable use of the mouse for all modes
vim.api.nvim_set_option('mouse', 'a')

-- Set the command window height to 2 lines, to avoid many cases of having to
-- "press <Enter> to continue"
vim.api.nvim_set_option('cmdheight', 1)

-- Display line numbers on the left
vim.wo.number = true
vim.wo.relativenumber = true

-- Quickly time out on keycodes, but never time out on mappings
vim.cmd('set notimeout ttimeout ttimeoutlen=200')

-- Use <F11> to toggle between 'paste' and 'nopaste'
vim.api.nvim_set_option('pastetoggle', '<F11>')

-- Use intuitive split location
vim.api.nvim_set_option('splitright', true)
vim.api.nvim_set_option('splitbelow', true)

-------------------------------------------------------------------------------

-- Indentation options
-- Indentation settings according to personal preference.

-- Indentation settings for using 4 spaces instead of tabs.
-- Do not change 'tabstop' from its default value of 8 with this setup.
vim.cmd([[
set tabstop=4
set shiftwidth=4
set softtabstop=4
set expandtab
]])

-------------------------------------------------------------------------------

-- language server | autocomplete | lsp
vim.api.nvim_set_option('completeopt', 'menu,menuone,noselect')
-- Setup nvim-cmp.
local cmp = require'cmp'

cmp.setup({
  snippet = {
    -- REQUIRED - you must specify a snippet engine
    expand = function(args)
      vim.fn["UltiSnips#Anon"](args.body) -- For `ultisnips` users.
    end,
  },

  mapping = {
    ['<C-j>'] = cmp.mapping(cmp.mapping.select_next_item(), { 'i', 'c' }),
    ['<C-k>'] = cmp.mapping(cmp.mapping.select_prev_item(), { 'i', 'c' }),
    ['<C-Space>'] = cmp.mapping(cmp.mapping.complete(), { 'i', 'c' }),
    ['<C-y>'] = cmp.config.disable, -- Specify `cmp.config.disable` if you want to remove the default `<C-y>` mapping.
    ['<C-e>'] = cmp.mapping({
      i = cmp.mapping.abort(),
      c = cmp.mapping.close(),
    }),
    -- Accept currently selected item. If none selected, `select` first item.
    -- Set `select` to `false` to only confirm explicitly selected items.
    ['<CR>'] = cmp.mapping.confirm({ select = true }),
  },
  sources = {
      { name = 'path' },
      { name = 'nvim_lsp' },
      { name = 'nvim_lua' },
      { name = 'ultisnips' },
      { name = 'buffer' }
  },
})

-- Autocomplete searching
require'cmp'.setup.cmdline('/', {
  sources = {
    { name = 'buffer' }
  }
})

-- Autocomplete Commands
require'cmp'.setup.cmdline(':', {
  sources = {
    { name = 'path' },
    { name = 'cmdline' }
  }
})

-- Setup lspconfig.
local capabilities = require('cmp_nvim_lsp').update_capabilities(vim.lsp.protocol.make_client_capabilities())
require('lspconfig')['clangd'].setup{ capabilities = capabilities }
require('lspconfig')['cmake'].setup{ capabilities = capabilities }
require('lspconfig')['dockerls'].setup{ capabilities = capabilities }
require('lspconfig')['vimls'].setup{ capabilities = capabilities }
require('lspconfig')['texlab'].setup{
    capabilities = capabilities,
    filetypes = { 'tex', 'bib', 'md' }
}
require('lspconfig')['sumneko_lua'].setup{
    settings = {
        Lua = {
            runtime = {
                -- Tell the language server which version of Lua you're using (most likely LuaJIT in the case of Neovim)
                version = 'LuaJIT',
            },
            diagnostics = {
                -- Get the language server to recognize the `vim` global
                globals = {'vim'},
            },
            workspace = {
                -- Make the server aware of Neovim runtime files
                library = vim.api.nvim_get_runtime_file("", true),
                checkThirdParty = false,
            },
            -- Do not send telemetry data containing a randomized but unique identifier
            telemetry = {
                enable = false,
                },
        },
    },
    capabilities = capabilities
}
require'lspconfig'.rust_analyzer.setup{}
require'lspconfig'.pyright.setup{}

-------------------------------------------------------------------------------

require("toggleterm").setup()

-------------------------------------------------------------------------------

-- Keymaps
function ChangeLanguage()
    local languages = {
        {'', 'en_gb'}, -- Default (English)
        {'greek_utf-8', 'el'}
    }

    for i = 1, #languages do
        if vim.api.nvim_get_option('keymap') == languages[i][1] then
            vim.cmd(':set keymap=' .. languages[(i % #languages) + 1][1])
            vim.cmd(':setlocal spelllang=' .. languages[(i % #languages) + 1][2])
            return
        end
    end
end


-------------------------------------------------------------------------------

-- Use markdown.pandoc for everything
vim.cmd([[
augroup pandoc_syntax
    au! BufNewFile,BufFilePre,BufRead *.md set filetype=markdown.pandoc
augroup END
]])

-------------------------------------------------------------------------------

-- Treesitter Setup
require'nvim-treesitter.configs'.setup { highlight = { enable = true } }

-------------------------------------------------------------------------------

-- vim-cmake
vim.g.cmake_build_dir_location = 'build'
vim.g.cmake_default_config = ''
vim.g.cmake_root_markers = { 'build' }

-------------------------------------------------------------------------------

-- Neoformat

-- C/C++
vim.cmd([[
    let g:neoformat_cpp_clangformat = {
    \    'exe': 'clang-format',
    \    'args': ['--style="{IndentWidth: 4}"']
    \}
]])
vim.g.neoformat_enabled_cpp = { 'clangformat' }
vim.g.neoformat_enabled_c = { 'clangformat' }

vim.cmd('autocmd BufWritePre *c,*.cpp,*.h,*.hpp Neoformat')

-- CMake
vim.cmd([[
    let g:neoformat_cmake_cmakeformat = {
    \    'exe': 'cmake-format',
    \    'args': ['--tab-size 4']
    \}
]])
vim.g.neoformat_enabled_cmake = { 'cmakeformat' }

vim.cmd('autocmd BufWritePre CMakeLists.txt Neoformat')

-------------------------------------------------------------------------------

-- FLoaterm
vim.g.floaterm_wintype = 'split'
vim.g.floaterm_width = 0.4

-------------------------------------------------------------------------------

-- Color Scheme
-- Make background transparent
vim.cmd("autocmd ColorScheme * highlight Normal ctermbg=NONE guibg=NONE")
vim.cmd("colorscheme dracula")
vim.api.nvim_set_option('termguicolors', true)

-------------------------------------------------------------------------------

-- NERD Commenter
vim.g.NERDCreateDefaultMappings = 0
vim.g.NERDSpaceDelims = 1

-------------------------------------------------------------------------------

-- Vim Airline
vim.g.airline_theme = 'dracula'

-------------------------------------------------------------------------------

-- Git Gutter
vim.g.gitgutter_enabled = 1
vim.g.gitgutter_map_keys = 0

-------------------------------------------------------------------------------

-- hexokinase
vim.g.Hexokinase_highlighters = { 'backgroundfull' }

-------------------------------------------------------------------------------

-- Vim QuickScope
vim.g.qs_highlight_on_keys = { 'f', 'F', 't', 'T' }

vim.cmd([[
highlight QuickScopePrimary guifg='#afff5f' gui=underline ctermfg=155 cterm=underline
highlight QuickScopeSecondary guifg='#5fffff' gui=underline ctermfg=81 cterm=underline
]])

-------------------------------------------------------------------------------

-- Vimtex

vim.g.vimtex_mappings_enabled = 0
vim.g.vimtex_syntax_enabled = 0

-------------------------------------------------------------------------------
