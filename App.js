import React, { useEffect, useState, useCallback } from 'react';
import {
  SafeAreaView, View, Text, TextInput, TouchableOpacity, StyleSheet,
  ScrollView, Alert, ActivityIndicator,
} from 'react-native';
import * as SecureStore from 'expo-secure-store';
import * as Clipboard from 'expo-clipboard';
import {
  parseWif, getUtxos, buildSignedTx, broadcast, zecToZat, zatToZec, feeFor,
} from './zcash';

const KEY = 'zec_wif';

export default function App() {
  const [wif, setWif] = useState(null);
  const [input, setInput] = useState('');
  const [address, setAddress] = useState('');
  const [balance, setBalance] = useState(null);
  const [to, setTo] = useState('');
  const [amount, setAmount] = useState('');
  const [busy, setBusy] = useState(false);
  const [txid, setTxid] = useState('');

  useEffect(() => {
    SecureStore.getItemAsync(KEY).then((v) => v && load(v));
  }, []);

  const refresh = useCallback(async (w) => {
    setBusy(true);
    try {
      const { address: a } = parseWif(w);
      const utxos = await getUtxos(a);
      setBalance(utxos.reduce((s, u) => s + BigInt(u.value), 0n));
    } catch (e) {
      Alert.alert('Xato', e.message);
    } finally {
      setBusy(false);
    }
  }, []);

  const load = (w) => {
    const { address: a } = parseWif(w);
    setWif(w);
    setAddress(a);
    refresh(w);
  };

  const doImport = async () => {
    try {
      parseWif(input); // tekshirish
      await SecureStore.setItemAsync(KEY, input.trim());
      load(input.trim());
      setInput('');
    } catch (e) {
      Alert.alert('Import xatosi', e.message);
    }
  };

  const logout = () =>
    Alert.alert('Hamyonni o‘chirish', 'Kalit qurilmadan o‘chiriladi. WIF zaxirangiz bormi?', [
      { text: 'Bekor' },
      {
        text: 'O‘chirish', style: 'destructive',
        onPress: async () => {
          await SecureStore.deleteItemAsync(KEY);
          setWif(null); setAddress(''); setBalance(null); setTxid('');
        },
      },
    ]);

  const send = async () => {
    try {
      const amt = zecToZat(amount);
      const utxos = await getUtxos(address);
      const { hex, fee } = buildSignedTx({ wif, utxos, to: to.trim(), amount: amt });
      Alert.alert(
        'Tasdiqlang',
        `Qabul qiluvchi:\n${to.trim()}\n\nMiqdor: ${zatToZec(amt)} ZEC\nKomissiya: ${zatToZec(fee)} ZEC`,
        [
          { text: 'Bekor' },
          {
            text: 'Yuborish',
            onPress: async () => {
              setBusy(true);
              try {
                const id = await broadcast(hex);
                setTxid(id); setTo(''); setAmount('');
                refresh(wif);
              } catch (e) {
                Alert.alert('Yuborilmadi', e.message);
              } finally {
                setBusy(false);
              }
            },
          },
        ]
      );
    } catch (e) {
      Alert.alert('Xato', e.message);
    }
  };

  if (!wif) {
    return (
      <SafeAreaView style={s.root}>
        <View style={s.pad}>
          <Text style={s.title}>Zcash (transparent)</Text>
          <Text style={s.label}>WIF maxfiy kalitni kiriting</Text>
          <TextInput
            style={s.input} value={input} onChangeText={setInput}
            placeholder="K... / L... / 5..." placeholderTextColor="#777"
            autoCapitalize="none" autoCorrect={false} secureTextEntry multiline={false}
          />
          <TouchableOpacity style={s.btn} onPress={doImport}>
            <Text style={s.btnT}>Import qilish</Text>
          </TouchableOpacity>
          <Text style={s.hint}>Kalit faqat qurilmaning xavfsiz xotirasida saqlanadi.</Text>
        </View>
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView style={s.root}>
      <ScrollView contentContainerStyle={s.pad}>
        <Text style={s.title}>Zcash hamyon</Text>
        <View style={s.card}>
          <Text style={s.label}>Balans</Text>
          <Text style={s.bal}>{balance === null ? '…' : zatToZec(balance)} ZEC</Text>
          <Text style={s.label}>Manzil (bosib nusxalang)</Text>
          <Text style={s.addr} onPress={() => { Clipboard.setStringAsync(address); Alert.alert('Nusxalandi'); }}>
            {address}
          </Text>
          <TouchableOpacity onPress={() => refresh(wif)}><Text style={s.link}>Yangilash</Text></TouchableOpacity>
        </View>

        <Text style={s.label}>Qabul qiluvchi (t1…)</Text>
        <TextInput style={s.input} value={to} onChangeText={setTo} autoCapitalize="none" autoCorrect={false}
          placeholder="t1..." placeholderTextColor="#777" />
        <Text style={s.label}>Miqdor (ZEC)</Text>
        <TextInput style={s.input} value={amount} onChangeText={setAmount} keyboardType="decimal-pad"
          placeholder="0.001" placeholderTextColor="#777" />
        <TouchableOpacity style={s.btn} onPress={send} disabled={busy}>
          {busy ? <ActivityIndicator color="#000" /> : <Text style={s.btnT}>Yuborish</Text>}
        </TouchableOpacity>
        <Text style={s.hint}>Komissiya taxminan {zatToZec(feeFor(1))} ZEC (ZIP-317).</Text>
        {!!txid && <Text style={s.addr} selectable>TXID: {txid}</Text>}

        <TouchableOpacity onPress={logout}><Text style={[s.link, { color: '#e55', marginTop: 30 }]}>Hamyonni o‘chirish</Text></TouchableOpacity>
      </ScrollView>
    </SafeAreaView>
  );
}

const s = StyleSheet.create({
  root: { flex: 1, backgroundColor: '#0f1115' },
  pad: { padding: 20 },
  title: { color: '#f4b728', fontSize: 26, fontWeight: '700', marginBottom: 16 },
  card: { backgroundColor: '#1a1d24', borderRadius: 14, padding: 16, marginBottom: 20 },
  label: { color: '#9aa', fontSize: 13, marginTop: 10, marginBottom: 4 },
  bal: { color: '#fff', fontSize: 28, fontWeight: '700' },
  addr: { color: '#cde', fontSize: 13, marginTop: 6 },
  input: { backgroundColor: '#1a1d24', color: '#fff', borderRadius: 10, padding: 12, fontSize: 15 },
  btn: { backgroundColor: '#f4b728', borderRadius: 10, padding: 14, alignItems: 'center', marginTop: 16 },
  btnT: { color: '#000', fontWeight: '700', fontSize: 16 },
  link: { color: '#f4b728', marginTop: 10 },
  hint: { color: '#789', fontSize: 12, marginTop: 10 },
});
