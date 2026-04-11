import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../crypto/ecdsa_service.dart';
import '../crypto/sha256_service.dart';

// ============================================================
// Root screen — two tabs
// ============================================================

class HomeScreen extends StatelessWidget {
  const HomeScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return DefaultTabController(
      length: 2,
      child: Scaffold(
        appBar: AppBar(
          backgroundColor: const Color(0xFF4F46E5),
          foregroundColor: Colors.white,
          title: const Text('Hashing + ECDSA P-256'),
          bottom: const TabBar(
            labelColor: Colors.white,
            unselectedLabelColor: Colors.white70,
            indicatorColor: Colors.white,
            tabs: [
              Tab(text: 'SHA-256'),
              Tab(text: 'ECDSA P-256'),
            ],
          ),
        ),
        body: const TabBarView(
          children: [
            _Sha256Tab(),
            _EcdsaTab(),
          ],
        ),
      ),
    );
  }
}

// ============================================================
// SHA-256 tab
// ============================================================

class _Sha256Tab extends StatefulWidget {
  const _Sha256Tab();

  @override
  State<_Sha256Tab> createState() => _Sha256TabState();
}

class _Sha256TabState extends State<_Sha256Tab> {
  final _inputController = TextEditingController();
  String _hashOutput = '';

  @override
  void dispose() {
    _inputController.dispose();
    super.dispose();
  }

  void _hash() {
    setState(() {
      _hashOutput = Sha256Service.hash(_inputController.text);
    });
  }

  @override
  Widget build(BuildContext context) {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          _Card(
            title: 'SHA-256 HASHING',
            children: [
              _FieldLabel('Input text'),
              TextField(
                controller: _inputController,
                maxLines: 4,
                decoration: const InputDecoration(
                  hintText: 'Type or paste text here…',
                  border: OutlineInputBorder(),
                ),
              ),
              const SizedBox(height: 12),
              ElevatedButton(
                onPressed: _hash,
                child: const Text('Hash'),
              ),
              if (_hashOutput.isNotEmpty) ...[
                const SizedBox(height: 16),
                _HexOutput(
                  label: 'SHA-256 digest',
                  hint: '64 hex chars · 32 bytes',
                  value: _hashOutput,
                ),
              ],
            ],
          ),
        ],
      ),
    );
  }
}

// ============================================================
// ECDSA P-256 tab
// ============================================================

// SG-M3: signature encoding modes
enum _SigEncoding { raw, der }

class _EcdsaTab extends StatefulWidget {
  const _EcdsaTab();

  @override
  State<_EcdsaTab> createState() => _EcdsaTabState();
}

class _EcdsaTabState extends State<_EcdsaTab> {
  EcdsaKeypair? _keypair;

  // Editable controllers for fields the user may tamper with (tampering tests)
  final _publicKeyController = TextEditingController();
  final _signatureController = TextEditingController();

  // Read-only display fields
  final _privateKeyController = TextEditingController();

  // Shared sign/verify message field (FR-3.4)
  final _messageController = TextEditingController();

  String? _verifyResult; // 'VALID' | 'INVALID' | null
  String? _errorMessage;

  // SG-M3: which encoding is shown in the signature field
  _SigEncoding _sigEncoding = _SigEncoding.raw;

  @override
  void dispose() {
    _publicKeyController.dispose();
    _privateKeyController.dispose();
    _messageController.dispose();
    _signatureController.dispose();
    super.dispose();
  }

  // ----------------------------------------------------------
  // Actions
  // ----------------------------------------------------------

  void _generateKeypair() {
    try {
      final keypair = EcdsaService.generateKeypair();
      setState(() {
        _keypair = keypair;
        _publicKeyController.text = keypair.publicKeyHex;
        _privateKeyController.text = keypair.privateKeyHex;
        // FR-2.5: clear stale signature and verification result
        _signatureController.text = '';
        _verifyResult = null;
        _errorMessage = null;
      });
    } catch (e) {
      setState(() => _errorMessage = e.toString());
    }
  }

  void _sign() {
    setState(() {
      _verifyResult = null;
      _errorMessage = null;
    });
    try {
      final rawSig = EcdsaService.sign(_messageController.text, _keypair);
      setState(() {
        // SG-M3: display in the currently selected encoding
        _signatureController.text = _sigEncoding == _SigEncoding.raw
            ? rawSig
            : EcdsaService.rawToDer(rawSig);
        // FR-3.4: message stays in the shared field — no copy needed
      });
    } on EcdsaException catch (e) {
      setState(() => _errorMessage = e.message);
    } catch (e) {
      setState(() => _errorMessage = e.toString());
    }
  }

  void _verify() {
    setState(() {
      _verifyResult = null;
      _errorMessage = null;
    });

    // FR-4.3: check empty before attempting format conversion
    final sigField = _signatureController.text.trim();
    if (sigField.isEmpty) {
      setState(() => _errorMessage =
          'No signature to verify. Sign a message first.');
      return;
    }

    // SG-M3: convert DER → raw before passing to the service
    String rawSig;
    if (_sigEncoding == _SigEncoding.der) {
      try {
        rawSig = EcdsaService.derToRaw(sigField);
      } on EcdsaException catch (e) {
        setState(() => _errorMessage = e.message);
        return;
      }
    } else {
      rawSig = sigField;
    }

    try {
      final valid = EcdsaService.verify(
        _messageController.text,
        rawSig,
        _publicKeyController.text.trim(),
      );
      setState(() => _verifyResult = valid ? 'VALID' : 'INVALID');
    } on EcdsaException catch (e) {
      setState(() => _errorMessage = e.message);
    } catch (e) {
      setState(() => _errorMessage = e.toString());
    }
  }

  // SG-M3: convert the displayed signature when the toggle changes
  void _onEncodingChanged(_SigEncoding encoding) {
    final current = _signatureController.text.trim();
    setState(() {
      _sigEncoding = encoding;
      _verifyResult = null;
      _errorMessage = null;
      if (current.isEmpty) return;
      try {
        _signatureController.text = encoding == _SigEncoding.der
            ? EcdsaService.rawToDer(current)    // raw → DER
            : EcdsaService.derToRaw(current);   // DER → raw
      } catch (_) {
        // Field content can't be converted (e.g. manually edited garbage) — clear it
        _signatureController.text = '';
      }
    });
  }

  // ----------------------------------------------------------
  // Build
  // ----------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          // ---- Key generation ----
          _Card(
            title: 'KEY GENERATION',
            children: [
              ElevatedButton(
                onPressed: _generateKeypair,
                child: const Text('Generate Keypair'),
              ),
              const SizedBox(height: 12),
              Row(children: [
                Expanded(child: _FieldLabel('Public key — uncompressed (04 ‖ X ‖ Y)')),
                _CopyIconButton(getText: () => _publicKeyController.text),
              ]),
              _HexHint('130 hex chars · 65 bytes · editable for tamper testing'),
              const SizedBox(height: 4),
              TextField(
                controller: _publicKeyController,
                maxLines: 3,
                style: _monoStyle,
                decoration: const InputDecoration(
                  hintText: 'public key will appear here',
                  border: OutlineInputBorder(),
                ),
              ),
              const SizedBox(height: 12),
              Row(children: [
                Expanded(child: _FieldLabel('Private key scalar d')),
                _CopyIconButton(getText: () => _privateKeyController.text),
              ]),
              _HexHint('64 hex chars · 32 bytes · display only'),
              const SizedBox(height: 4),
              TextField(
                controller: _privateKeyController,
                readOnly: true,
                maxLines: 2,
                style: _monoStyle.copyWith(color: Colors.grey[600]),
                decoration: InputDecoration(
                  hintText: 'private key will appear here',
                  border: const OutlineInputBorder(),
                  fillColor: Colors.grey[100],
                  filled: true,
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),

          // ---- Sign / Verify ----
          _Card(
            title: 'SIGN / VERIFY',
            children: [
              _FieldLabel('Message'),
              TextField(
                controller: _messageController,
                maxLines: 3,
                decoration: const InputDecoration(
                  hintText: 'Type a message to sign…',
                  border: OutlineInputBorder(),
                ),
              ),
              const SizedBox(height: 12),
              Row(
                children: [
                  Expanded(
                    child: ElevatedButton(
                      onPressed: _sign,
                      child: const Text('Sign'),
                    ),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: ElevatedButton(
                      onPressed: _verify,
                      child: const Text('Verify'),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 12),
              // SG-M3: encoding toggle
              SegmentedButton<_SigEncoding>(
                segments: const [
                  ButtonSegment(
                    value: _SigEncoding.raw,
                    label: Text('Raw (r ‖ s)'),
                  ),
                  ButtonSegment(
                    value: _SigEncoding.der,
                    label: Text('DER'),
                  ),
                ],
                selected: {_sigEncoding},
                onSelectionChanged: (s) => _onEncodingChanged(s.first),
              ),
              const SizedBox(height: 10),
              Row(children: [
                Expanded(
                  child: _FieldLabel(
                    _sigEncoding == _SigEncoding.raw
                        ? 'Signature (r ‖ s)'
                        : 'Signature (DER)',
                  ),
                ),
                _CopyIconButton(getText: () => _signatureController.text),
              ]),
              _HexHint(
                _sigEncoding == _SigEncoding.raw
                    ? '128 hex chars · 64 bytes · editable for tamper testing'
                    : 'ASN.1 DER-encoded · variable length · editable for tamper testing',
              ),
              const SizedBox(height: 4),
              TextField(
                controller: _signatureController,
                maxLines: 3,
                style: _monoStyle,
                decoration: const InputDecoration(
                  hintText: 'signature will appear here after signing',
                  border: OutlineInputBorder(),
                ),
              ),
              if (_verifyResult != null) ...[
                const SizedBox(height: 12),
                _VerifyBanner(result: _verifyResult!),
              ],
              if (_errorMessage != null) ...[
                const SizedBox(height: 8),
                _ErrorBanner(message: _errorMessage!),
              ],
            ],
          ),
        ],
      ),
    );
  }
}

// ============================================================
// Shared helper widgets
// ============================================================

const _monoStyle = TextStyle(fontFamily: 'monospace', fontSize: 11.5);

class _Card extends StatelessWidget {
  final String title;
  final List<Widget> children;

  const _Card({required this.title, required this.children});

  @override
  Widget build(BuildContext context) {
    return Card(
      elevation: 1,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(
              title,
              style: TextStyle(
                fontSize: 11,
                fontWeight: FontWeight.bold,
                color: Colors.grey[600],
                letterSpacing: 0.8,
              ),
            ),
            const SizedBox(height: 14),
            ...children,
          ],
        ),
      ),
    );
  }
}

class _FieldLabel extends StatelessWidget {
  final String text;
  const _FieldLabel(this.text);

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 2),
      child: Text(
        text,
        style: const TextStyle(fontWeight: FontWeight.w600, fontSize: 13),
      ),
    );
  }
}

class _HexHint extends StatelessWidget {
  final String text;
  const _HexHint(this.text);

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 2),
      child: Text(
        text,
        style: TextStyle(fontSize: 11, color: Colors.grey[600]),
      ),
    );
  }
}

class _HexOutput extends StatelessWidget {
  final String label;
  final String hint;
  final String value;

  const _HexOutput({
    required this.label,
    required this.hint,
    required this.value,
  });

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Expanded(child: _FieldLabel(label)),
            _CopyIconButton(getText: () => value),
          ],
        ),
        _HexHint(hint),
        const SizedBox(height: 4),
        Container(
          width: double.infinity,
          padding: const EdgeInsets.all(10),
          decoration: BoxDecoration(
            color: Colors.grey[100],
            border: Border.all(color: Colors.grey[300]!),
            borderRadius: BorderRadius.circular(6),
          ),
          child: SelectableText(value, style: _monoStyle),
        ),
      ],
    );
  }
}

class _CopyIconButton extends StatelessWidget {
  final String Function() getText;
  const _CopyIconButton({required this.getText});

  @override
  Widget build(BuildContext context) {
    return IconButton(
      icon: const Icon(Icons.content_copy, size: 16),
      tooltip: 'Copy to clipboard',
      padding: EdgeInsets.zero,
      constraints: const BoxConstraints(),
      onPressed: () {
        final text = getText();
        if (text.isNotEmpty) {
          Clipboard.setData(ClipboardData(text: text));
        }
      },
    );
  }
}

class _VerifyBanner extends StatelessWidget {
  final String result;
  const _VerifyBanner({required this.result});

  @override
  Widget build(BuildContext context) {
    final isValid = result == 'VALID';
    return Container(
      padding: const EdgeInsets.symmetric(vertical: 12),
      decoration: BoxDecoration(
        color: isValid ? Colors.green[50] : Colors.red[50],
        border: Border.all(
          color: isValid ? Colors.green[300]! : Colors.red[300]!,
        ),
        borderRadius: BorderRadius.circular(6),
      ),
      child: Text(
        result,
        textAlign: TextAlign.center,
        style: TextStyle(
          fontSize: 20,
          fontWeight: FontWeight.bold,
          letterSpacing: 1.2,
          color: isValid ? Colors.green[800] : Colors.red[800],
        ),
      ),
    );
  }
}

class _ErrorBanner extends StatelessWidget {
  final String message;
  const _ErrorBanner({required this.message});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(10),
      decoration: BoxDecoration(
        color: Colors.orange[50],
        border: Border.all(color: Colors.orange[300]!),
        borderRadius: BorderRadius.circular(6),
      ),
      child: Text(
        message,
        style: TextStyle(color: Colors.orange[900], fontSize: 13),
      ),
    );
  }
}
