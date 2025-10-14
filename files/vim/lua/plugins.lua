-- Bootstrap lazy.nvim
local lazypath = vim.fn.stdpath("data") .. "/lazy/lazy.nvim"
if not (vim.uv or vim.loop).fs_stat(lazypath) then
    local lazyrepo = "https://github.com/folke/lazy.nvim.git"
    local out = vim.fn.system({ "git", "clone", "--filter=blob:none", "--branch=stable", lazyrepo, lazypath })
    if vim.v.shell_error ~= 0 then
        vim.api.nvim_echo({
            { "Failed to clone lazy.nvim:\n", "ErrorMsg" },
            { out,                            "WarningMsg" },
            { "\nPress any key to exit..." },
        }, true, {})
        vim.fn.getchar()
        os.exit(1)
    end
end
vim.opt.rtp:prepend(lazypath)

local plugins = {
    -- LSP
    'williamboman/mason.nvim',
    'williamboman/mason-lspconfig.nvim',
    'neovim/nvim-lspconfig',
    -- 'jose-elias-alvarez/null-ls.nvim',
    'nvimtools/none-ls.nvim',

    'hrsh7th/cmp-nvim-lsp',
    'hrsh7th/cmp-nvim-lua',
    'hrsh7th/cmp-buffer',
    'hrsh7th/cmp-path',
    'hrsh7th/cmp-cmdline',
    'hrsh7th/nvim-cmp',

    'nvim-treesitter/nvim-treesitter',
    'nvim-treesitter/playground',

    'cdelledonne/vim-cmake',

    -- Debugger,
    'mfussenegger/nvim-dap',
    'nvim-telescope/telescope-dap.nvim',
    'theHamsta/nvim-dap-virtual-text',
    'rcarriga/nvim-dap-ui',
    'nvim-neotest/nvim-nio',

    -- navigation,
    'nvim-lua/plenary.nvim',
    'nvim-telescope/telescope.nvim',
    'nvim-telescope/telescope-fzy-native.nvim',
    'ChSotiriou/nvim-telemake',

    'stevearc/oil.nvim',

    -- syntax,
    'dpelle/vim-languagetool',
    'PotatoesMaster/i3-vim-syntax',
    'kelwin/vim-smali',
    'VebbNix/lf-vim',
    'vim-pandoc/vim-pandoc-syntax',
    'dhruvasagar/vim-table-mode',
    'lervag/vimtex',

    'tpope/vim-commentary',
    'tpope/vim-surround',
    'jiangmiao/auto-pairs',

    'ryanoasis/vim-devicons',

    'vim-airline/vim-airline',
    'vim-airline/vim-airline-themes',
    { 'dracula/vim',           as = 'dracula' },
    'unblevable/quick-scope',

    'junegunn/fzf.vim',

    'airblade/vim-gitgutter',
    'NeogitOrg/neogit',

    "akinsho/toggleterm.nvim",

    "christoomey/vim-tmux-navigator",

    { "L3MON4D3/LuaSnip", build = "make install_jsregexp" },
    'saadparwaiz1/cmp_luasnip',
}

local opts = {}
require("lazy").setup(plugins, opts)
