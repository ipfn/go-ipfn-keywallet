// Copyright © 2017-2018 The IPFN Developers. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// # References
//
// * [BIP0032](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) - Hierarchical Deterministic Wallets
// * [BIP0039](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) - Mnemonic code for generating deterministic keys
// * [BIP0043](https://github.com/bitcoin/bips/blob/master/bip-0043.mediawiki) - Purpose Field for Deterministic Wallets
// * [BIP0044](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki) - Multi-Account Hierarchy for Deterministic Wallets
// * [SLIP-0044](https://github.com/satoshilabs/slips/blob/master/slip-0044.md) - Registered coin types for BIP-0044
// * [Mnemonic code converter](https://iancoleman.io/bip39/) - Browser UI implementation

// Package wallet implements cryptographic key wallet.
package wallet

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/ipfn/go-ipfn-cmd-util/logger"
	"github.com/ipfn/go-ipfn-keypair"
	"github.com/ipfn/go-ipfn-store"
)

// Wallet - Storage based key wallet.
type Wallet struct {
	store store.EncodedStore

	mutex    *sync.RWMutex
	unlocked map[string]*keypair.KeyPair
}

// New - Creates new key wallet using storage.
func New(store store.EncodedStore) *Wallet {
	return &Wallet{
		store:    store,
		mutex:    new(sync.RWMutex),
		unlocked: make(map[string]*keypair.KeyPair),
	}
}

// NewDefault - Creates new default wallet.
func NewDefault() *Wallet {
	return New(store.NewFileJSONStore(defaultWalletPath))
}

// KeyByPath - Creates a new key by path from default wallet.
func KeyByPath(src, password string) (_ *keypair.KeyPair, err error) {
	path, err := ParseKeyPath(src)
	if err != nil {
		return
	}
	return NewDefault().DeriveKey(path, []byte(password))
}

// MasterKey - Finds master key by name and decrypts using password.
func (w *Wallet) MasterKey(name string, password []byte) (_ *keypair.KeyPair, err error) {
	key, err := w.ExportKey(name)
	if err != nil {
		return
	}
	return key.ToKeyPair(password)
}

// DeriveKey - Finds master key by name, decrypts using password and derives path.
// Path should be BIP32 compatible otherwise operation will fail.
func (w *Wallet) DeriveKey(path *KeyPath, password []byte) (_ *keypair.KeyPair, err error) {
	master, err := w.MasterKey(path.SeedName, password)
	if err != nil {
		return nil, fmt.Errorf("wallet: %v", err)
	}
	if !path.HasPath() {
		return master, nil
	}
	return master.DerivePath(path.DerivationPath)
}

// DeriveKeyPath - Parses key path from string and derives key.
func (w *Wallet) DeriveKeyPath(src string, password []byte) (_ *keypair.KeyPair, err error) {
	path, err := ParseKeyPath(src)
	if err != nil {
		return
	}
	return w.DeriveKey(path, password)
}

// CreateSeed - Creates new wallet key seed.
func (w *Wallet) CreateSeed(name string, password []byte) (seed []byte, err error) {
	seed, err = keypair.NewSeed()
	if err != nil {
		return
	}
	err = w.ImportKey(name, seed, password)
	return
}

// KeyNames - Returns names of all seeds in wallet.
func (w *Wallet) KeyNames() (keys []string, err error) {
	return w.prefixKeys("seed.")
}

// KeyExists - Checks if has key under given name.
func (w *Wallet) KeyExists(name string) (ok bool, err error) {
	return w.store.Has(seedKey(name))
}

// ImportKey - Imports master key and encrypts with password.
func (w *Wallet) ImportKey(name string, seed, password []byte) (err error) {
	key, err := keypair.EncryptSeed(name, seed, password)
	if err != nil {
		return
	}
	return w.store.Put(seedKey(name), &key)
}

// ExportKey - Gets master key by name and decrypts using given password.
// Returns true if value is mnemonic seed, otherwise false.
func (w *Wallet) ExportKey(name string) (key keypair.EncryptedSeed, err error) {
	err = w.store.Get(seedKey(name), &key)
	if err != nil {
		return
	}
	return key, nil
}

// Unlock - Unlocks master key.
func (w *Wallet) Unlock(name string, password []byte) (key *keypair.KeyPair, err error) {
	if w.IsUnlocked(name) {
		return nil, fmt.Errorf("wallet %q already unlocked", err)
	}
	seed, err := w.ExportKey(name)
	if err != nil {
		return
	}
	key, err = seed.ToKeyPair(password)
	if err != nil {
		return
	}
	w.mutex.Lock()
	w.unlocked[name] = key
	w.mutex.Unlock()
	return
}

// UnlockedKey - Returns key if unlocked otherwise returns an error.
func (w *Wallet) UnlockedKey(name string) (key *keypair.KeyPair, err error) {
	w.mutex.RLock()
	key = w.unlocked[name]
	w.mutex.RUnlock()
	if key == nil {
		return nil, fmt.Errorf("wallet %q is locked or not found", err)
	}
	return
}

// UnlockedDerive - Derives key from unlocked wallet.
func (w *Wallet) UnlockedDerive(path *KeyPath) (key *keypair.KeyPair, err error) {
	key, err = w.UnlockedKey(path.SeedName)
	if err != nil {
		return nil, fmt.Errorf("wallet: %v", err)
	}
	if path.DerivationPath != "" {
		key, err = key.DerivePath(path.DerivationPath)
	}
	return
}

// IsUnlocked - Returns true is key under name is unlocked.
func (w *Wallet) IsUnlocked(name string) bool {
	w.mutex.RLock()
	found := w.unlocked[name] != nil
	w.mutex.RUnlock()
	return found
}

func (w *Wallet) prefixKeys(prefix string) (keys []string, err error) {
	keys, err = w.store.Keys()
	if err != nil {
		return
	}
	for i := 0; i < len(keys); i++ {
		if !strings.HasPrefix(keys[i], prefix) {
			continue
		}
		keys[i] = strings.TrimPrefix(keys[i], prefix)
	}
	return
}

func seedKey(name string) string {
	return strings.Join([]string{"seed", name}, ".")
}

func accountKey(name string) string {
	return strings.Join([]string{"account", name}, ".")
}

var defaultWalletPath string

func init() {
	env := "HOME"
	if runtime.GOOS == "windows" {
		env = "USERPROFILE"
	} else if runtime.GOOS == "plan9" {
		env = "home"
	}
	if home := os.Getenv(env); home != "" {
		defaultWalletPath = filepath.Join(home, ".ipfn", "wallet")
	}
	_, err := os.Stat(defaultWalletPath)
	if os.IsNotExist(err) {
		err = os.MkdirAll(defaultWalletPath, 0666)
	}
	if err != nil {
		logger.Error(err)
	}
}
