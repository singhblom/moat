// coverage:ignore-file
// GENERATED CODE - DO NOT MODIFY BY HAND
// ignore_for_file: type=lint
// ignore_for_file: unused_element, deprecated_member_use, deprecated_member_use_from_same_package, use_function_type_syntax_for_parameters, unnecessary_const, avoid_init_to_null, invalid_override_different_default_values_named, prefer_expression_function_bodies, annotate_overrides, invalid_annotation_target, unnecessary_question_mark

part of 'simple.dart';

// **************************************************************************
// FreezedGenerator
// **************************************************************************

T _$identity<T>(T value) => value;

final _privateConstructorUsedError = UnsupportedError(
    'It seems like you constructed your class using `MyClass._()`. This constructor is only meant to be used by freezed and you are not supposed to need it nor use it.\nPlease check the documentation here for more information: https://github.com/rrousselGit/freezed#adding-getters-and-methods-to-our-models');

/// @nodoc
mixin _$PairChannelCommandDto {
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(String drawbridgeUrl, Uint8List token)
        sendPairOffer,
    required TResult Function(String drawbridgeUrl, Uint8List token)
        sendPairJoin,
    required TResult Function(String url, Uint8List token) connectPair,
    required TResult Function(Uint8List data) sendFrame,
    required TResult Function() closePair,
    required TResult Function() dropPair,
    required TResult Function(Uint8List tag, Uint8List ciphertext)
        publishRingEvent,
    required TResult Function(Uint8List token) loadHistory,
    required TResult Function(String convId, List<SyncMessageDto> messages)
        storeMessages,
    required TResult Function() saveMlsState,
    required TResult Function() saveRingState,
    required TResult Function(Uint8List ringId) ringJoined,
    required TResult Function(Uint8List ringId) deviceAdmitted,
    required TResult Function(Uint8List deviceId, Uint8List scanPubkey)
        siblingStealthLearned,
    required TResult Function(SyncTallyDto tally) transferComplete,
    required TResult Function(String detail, bool duringPairing) transferFailed,
    required TResult Function(String line) log,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(String drawbridgeUrl, Uint8List token)? sendPairOffer,
    TResult? Function(String drawbridgeUrl, Uint8List token)? sendPairJoin,
    TResult? Function(String url, Uint8List token)? connectPair,
    TResult? Function(Uint8List data)? sendFrame,
    TResult? Function()? closePair,
    TResult? Function()? dropPair,
    TResult? Function(Uint8List tag, Uint8List ciphertext)? publishRingEvent,
    TResult? Function(Uint8List token)? loadHistory,
    TResult? Function(String convId, List<SyncMessageDto> messages)?
        storeMessages,
    TResult? Function()? saveMlsState,
    TResult? Function()? saveRingState,
    TResult? Function(Uint8List ringId)? ringJoined,
    TResult? Function(Uint8List ringId)? deviceAdmitted,
    TResult? Function(Uint8List deviceId, Uint8List scanPubkey)?
        siblingStealthLearned,
    TResult? Function(SyncTallyDto tally)? transferComplete,
    TResult? Function(String detail, bool duringPairing)? transferFailed,
    TResult? Function(String line)? log,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(String drawbridgeUrl, Uint8List token)? sendPairOffer,
    TResult Function(String drawbridgeUrl, Uint8List token)? sendPairJoin,
    TResult Function(String url, Uint8List token)? connectPair,
    TResult Function(Uint8List data)? sendFrame,
    TResult Function()? closePair,
    TResult Function()? dropPair,
    TResult Function(Uint8List tag, Uint8List ciphertext)? publishRingEvent,
    TResult Function(Uint8List token)? loadHistory,
    TResult Function(String convId, List<SyncMessageDto> messages)?
        storeMessages,
    TResult Function()? saveMlsState,
    TResult Function()? saveRingState,
    TResult Function(Uint8List ringId)? ringJoined,
    TResult Function(Uint8List ringId)? deviceAdmitted,
    TResult Function(Uint8List deviceId, Uint8List scanPubkey)?
        siblingStealthLearned,
    TResult Function(SyncTallyDto tally)? transferComplete,
    TResult Function(String detail, bool duringPairing)? transferFailed,
    TResult Function(String line)? log,
    required TResult orElse(),
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(PairChannelCommandDto_SendPairOffer value)
        sendPairOffer,
    required TResult Function(PairChannelCommandDto_SendPairJoin value)
        sendPairJoin,
    required TResult Function(PairChannelCommandDto_ConnectPair value)
        connectPair,
    required TResult Function(PairChannelCommandDto_SendFrame value) sendFrame,
    required TResult Function(PairChannelCommandDto_ClosePair value) closePair,
    required TResult Function(PairChannelCommandDto_DropPair value) dropPair,
    required TResult Function(PairChannelCommandDto_PublishRingEvent value)
        publishRingEvent,
    required TResult Function(PairChannelCommandDto_LoadHistory value)
        loadHistory,
    required TResult Function(PairChannelCommandDto_StoreMessages value)
        storeMessages,
    required TResult Function(PairChannelCommandDto_SaveMlsState value)
        saveMlsState,
    required TResult Function(PairChannelCommandDto_SaveRingState value)
        saveRingState,
    required TResult Function(PairChannelCommandDto_RingJoined value)
        ringJoined,
    required TResult Function(PairChannelCommandDto_DeviceAdmitted value)
        deviceAdmitted,
    required TResult Function(PairChannelCommandDto_SiblingStealthLearned value)
        siblingStealthLearned,
    required TResult Function(PairChannelCommandDto_TransferComplete value)
        transferComplete,
    required TResult Function(PairChannelCommandDto_TransferFailed value)
        transferFailed,
    required TResult Function(PairChannelCommandDto_Log value) log,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(PairChannelCommandDto_SendPairOffer value)? sendPairOffer,
    TResult? Function(PairChannelCommandDto_SendPairJoin value)? sendPairJoin,
    TResult? Function(PairChannelCommandDto_ConnectPair value)? connectPair,
    TResult? Function(PairChannelCommandDto_SendFrame value)? sendFrame,
    TResult? Function(PairChannelCommandDto_ClosePair value)? closePair,
    TResult? Function(PairChannelCommandDto_DropPair value)? dropPair,
    TResult? Function(PairChannelCommandDto_PublishRingEvent value)?
        publishRingEvent,
    TResult? Function(PairChannelCommandDto_LoadHistory value)? loadHistory,
    TResult? Function(PairChannelCommandDto_StoreMessages value)? storeMessages,
    TResult? Function(PairChannelCommandDto_SaveMlsState value)? saveMlsState,
    TResult? Function(PairChannelCommandDto_SaveRingState value)? saveRingState,
    TResult? Function(PairChannelCommandDto_RingJoined value)? ringJoined,
    TResult? Function(PairChannelCommandDto_DeviceAdmitted value)?
        deviceAdmitted,
    TResult? Function(PairChannelCommandDto_SiblingStealthLearned value)?
        siblingStealthLearned,
    TResult? Function(PairChannelCommandDto_TransferComplete value)?
        transferComplete,
    TResult? Function(PairChannelCommandDto_TransferFailed value)?
        transferFailed,
    TResult? Function(PairChannelCommandDto_Log value)? log,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(PairChannelCommandDto_SendPairOffer value)? sendPairOffer,
    TResult Function(PairChannelCommandDto_SendPairJoin value)? sendPairJoin,
    TResult Function(PairChannelCommandDto_ConnectPair value)? connectPair,
    TResult Function(PairChannelCommandDto_SendFrame value)? sendFrame,
    TResult Function(PairChannelCommandDto_ClosePair value)? closePair,
    TResult Function(PairChannelCommandDto_DropPair value)? dropPair,
    TResult Function(PairChannelCommandDto_PublishRingEvent value)?
        publishRingEvent,
    TResult Function(PairChannelCommandDto_LoadHistory value)? loadHistory,
    TResult Function(PairChannelCommandDto_StoreMessages value)? storeMessages,
    TResult Function(PairChannelCommandDto_SaveMlsState value)? saveMlsState,
    TResult Function(PairChannelCommandDto_SaveRingState value)? saveRingState,
    TResult Function(PairChannelCommandDto_RingJoined value)? ringJoined,
    TResult Function(PairChannelCommandDto_DeviceAdmitted value)?
        deviceAdmitted,
    TResult Function(PairChannelCommandDto_SiblingStealthLearned value)?
        siblingStealthLearned,
    TResult Function(PairChannelCommandDto_TransferComplete value)?
        transferComplete,
    TResult Function(PairChannelCommandDto_TransferFailed value)?
        transferFailed,
    TResult Function(PairChannelCommandDto_Log value)? log,
    required TResult orElse(),
  }) =>
      throw _privateConstructorUsedError;
}

/// @nodoc
abstract class $PairChannelCommandDtoCopyWith<$Res> {
  factory $PairChannelCommandDtoCopyWith(PairChannelCommandDto value,
          $Res Function(PairChannelCommandDto) then) =
      _$PairChannelCommandDtoCopyWithImpl<$Res, PairChannelCommandDto>;
}

/// @nodoc
class _$PairChannelCommandDtoCopyWithImpl<$Res,
        $Val extends PairChannelCommandDto>
    implements $PairChannelCommandDtoCopyWith<$Res> {
  _$PairChannelCommandDtoCopyWithImpl(this._value, this._then);

  // ignore: unused_field
  final $Val _value;
  // ignore: unused_field
  final $Res Function($Val) _then;

  /// Create a copy of PairChannelCommandDto
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc
abstract class _$$PairChannelCommandDto_SendPairOfferImplCopyWith<$Res> {
  factory _$$PairChannelCommandDto_SendPairOfferImplCopyWith(
          _$PairChannelCommandDto_SendPairOfferImpl value,
          $Res Function(_$PairChannelCommandDto_SendPairOfferImpl) then) =
      __$$PairChannelCommandDto_SendPairOfferImplCopyWithImpl<$Res>;
  @useResult
  $Res call({String drawbridgeUrl, Uint8List token});
}

/// @nodoc
class __$$PairChannelCommandDto_SendPairOfferImplCopyWithImpl<$Res>
    extends _$PairChannelCommandDtoCopyWithImpl<$Res,
        _$PairChannelCommandDto_SendPairOfferImpl>
    implements _$$PairChannelCommandDto_SendPairOfferImplCopyWith<$Res> {
  __$$PairChannelCommandDto_SendPairOfferImplCopyWithImpl(
      _$PairChannelCommandDto_SendPairOfferImpl _value,
      $Res Function(_$PairChannelCommandDto_SendPairOfferImpl) _then)
      : super(_value, _then);

  /// Create a copy of PairChannelCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? drawbridgeUrl = null,
    Object? token = null,
  }) {
    return _then(_$PairChannelCommandDto_SendPairOfferImpl(
      drawbridgeUrl: null == drawbridgeUrl
          ? _value.drawbridgeUrl
          : drawbridgeUrl // ignore: cast_nullable_to_non_nullable
              as String,
      token: null == token
          ? _value.token
          : token // ignore: cast_nullable_to_non_nullable
              as Uint8List,
    ));
  }
}

/// @nodoc

class _$PairChannelCommandDto_SendPairOfferImpl
    extends PairChannelCommandDto_SendPairOffer {
  const _$PairChannelCommandDto_SendPairOfferImpl(
      {required this.drawbridgeUrl, required this.token})
      : super._();

  @override
  final String drawbridgeUrl;
  @override
  final Uint8List token;

  @override
  String toString() {
    return 'PairChannelCommandDto.sendPairOffer(drawbridgeUrl: $drawbridgeUrl, token: $token)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$PairChannelCommandDto_SendPairOfferImpl &&
            (identical(other.drawbridgeUrl, drawbridgeUrl) ||
                other.drawbridgeUrl == drawbridgeUrl) &&
            const DeepCollectionEquality().equals(other.token, token));
  }

  @override
  int get hashCode => Object.hash(
      runtimeType, drawbridgeUrl, const DeepCollectionEquality().hash(token));

  /// Create a copy of PairChannelCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$PairChannelCommandDto_SendPairOfferImplCopyWith<
          _$PairChannelCommandDto_SendPairOfferImpl>
      get copyWith => __$$PairChannelCommandDto_SendPairOfferImplCopyWithImpl<
          _$PairChannelCommandDto_SendPairOfferImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(String drawbridgeUrl, Uint8List token)
        sendPairOffer,
    required TResult Function(String drawbridgeUrl, Uint8List token)
        sendPairJoin,
    required TResult Function(String url, Uint8List token) connectPair,
    required TResult Function(Uint8List data) sendFrame,
    required TResult Function() closePair,
    required TResult Function() dropPair,
    required TResult Function(Uint8List tag, Uint8List ciphertext)
        publishRingEvent,
    required TResult Function(Uint8List token) loadHistory,
    required TResult Function(String convId, List<SyncMessageDto> messages)
        storeMessages,
    required TResult Function() saveMlsState,
    required TResult Function() saveRingState,
    required TResult Function(Uint8List ringId) ringJoined,
    required TResult Function(Uint8List ringId) deviceAdmitted,
    required TResult Function(Uint8List deviceId, Uint8List scanPubkey)
        siblingStealthLearned,
    required TResult Function(SyncTallyDto tally) transferComplete,
    required TResult Function(String detail, bool duringPairing) transferFailed,
    required TResult Function(String line) log,
  }) {
    return sendPairOffer(drawbridgeUrl, token);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(String drawbridgeUrl, Uint8List token)? sendPairOffer,
    TResult? Function(String drawbridgeUrl, Uint8List token)? sendPairJoin,
    TResult? Function(String url, Uint8List token)? connectPair,
    TResult? Function(Uint8List data)? sendFrame,
    TResult? Function()? closePair,
    TResult? Function()? dropPair,
    TResult? Function(Uint8List tag, Uint8List ciphertext)? publishRingEvent,
    TResult? Function(Uint8List token)? loadHistory,
    TResult? Function(String convId, List<SyncMessageDto> messages)?
        storeMessages,
    TResult? Function()? saveMlsState,
    TResult? Function()? saveRingState,
    TResult? Function(Uint8List ringId)? ringJoined,
    TResult? Function(Uint8List ringId)? deviceAdmitted,
    TResult? Function(Uint8List deviceId, Uint8List scanPubkey)?
        siblingStealthLearned,
    TResult? Function(SyncTallyDto tally)? transferComplete,
    TResult? Function(String detail, bool duringPairing)? transferFailed,
    TResult? Function(String line)? log,
  }) {
    return sendPairOffer?.call(drawbridgeUrl, token);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(String drawbridgeUrl, Uint8List token)? sendPairOffer,
    TResult Function(String drawbridgeUrl, Uint8List token)? sendPairJoin,
    TResult Function(String url, Uint8List token)? connectPair,
    TResult Function(Uint8List data)? sendFrame,
    TResult Function()? closePair,
    TResult Function()? dropPair,
    TResult Function(Uint8List tag, Uint8List ciphertext)? publishRingEvent,
    TResult Function(Uint8List token)? loadHistory,
    TResult Function(String convId, List<SyncMessageDto> messages)?
        storeMessages,
    TResult Function()? saveMlsState,
    TResult Function()? saveRingState,
    TResult Function(Uint8List ringId)? ringJoined,
    TResult Function(Uint8List ringId)? deviceAdmitted,
    TResult Function(Uint8List deviceId, Uint8List scanPubkey)?
        siblingStealthLearned,
    TResult Function(SyncTallyDto tally)? transferComplete,
    TResult Function(String detail, bool duringPairing)? transferFailed,
    TResult Function(String line)? log,
    required TResult orElse(),
  }) {
    if (sendPairOffer != null) {
      return sendPairOffer(drawbridgeUrl, token);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(PairChannelCommandDto_SendPairOffer value)
        sendPairOffer,
    required TResult Function(PairChannelCommandDto_SendPairJoin value)
        sendPairJoin,
    required TResult Function(PairChannelCommandDto_ConnectPair value)
        connectPair,
    required TResult Function(PairChannelCommandDto_SendFrame value) sendFrame,
    required TResult Function(PairChannelCommandDto_ClosePair value) closePair,
    required TResult Function(PairChannelCommandDto_DropPair value) dropPair,
    required TResult Function(PairChannelCommandDto_PublishRingEvent value)
        publishRingEvent,
    required TResult Function(PairChannelCommandDto_LoadHistory value)
        loadHistory,
    required TResult Function(PairChannelCommandDto_StoreMessages value)
        storeMessages,
    required TResult Function(PairChannelCommandDto_SaveMlsState value)
        saveMlsState,
    required TResult Function(PairChannelCommandDto_SaveRingState value)
        saveRingState,
    required TResult Function(PairChannelCommandDto_RingJoined value)
        ringJoined,
    required TResult Function(PairChannelCommandDto_DeviceAdmitted value)
        deviceAdmitted,
    required TResult Function(PairChannelCommandDto_SiblingStealthLearned value)
        siblingStealthLearned,
    required TResult Function(PairChannelCommandDto_TransferComplete value)
        transferComplete,
    required TResult Function(PairChannelCommandDto_TransferFailed value)
        transferFailed,
    required TResult Function(PairChannelCommandDto_Log value) log,
  }) {
    return sendPairOffer(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(PairChannelCommandDto_SendPairOffer value)? sendPairOffer,
    TResult? Function(PairChannelCommandDto_SendPairJoin value)? sendPairJoin,
    TResult? Function(PairChannelCommandDto_ConnectPair value)? connectPair,
    TResult? Function(PairChannelCommandDto_SendFrame value)? sendFrame,
    TResult? Function(PairChannelCommandDto_ClosePair value)? closePair,
    TResult? Function(PairChannelCommandDto_DropPair value)? dropPair,
    TResult? Function(PairChannelCommandDto_PublishRingEvent value)?
        publishRingEvent,
    TResult? Function(PairChannelCommandDto_LoadHistory value)? loadHistory,
    TResult? Function(PairChannelCommandDto_StoreMessages value)? storeMessages,
    TResult? Function(PairChannelCommandDto_SaveMlsState value)? saveMlsState,
    TResult? Function(PairChannelCommandDto_SaveRingState value)? saveRingState,
    TResult? Function(PairChannelCommandDto_RingJoined value)? ringJoined,
    TResult? Function(PairChannelCommandDto_DeviceAdmitted value)?
        deviceAdmitted,
    TResult? Function(PairChannelCommandDto_SiblingStealthLearned value)?
        siblingStealthLearned,
    TResult? Function(PairChannelCommandDto_TransferComplete value)?
        transferComplete,
    TResult? Function(PairChannelCommandDto_TransferFailed value)?
        transferFailed,
    TResult? Function(PairChannelCommandDto_Log value)? log,
  }) {
    return sendPairOffer?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(PairChannelCommandDto_SendPairOffer value)? sendPairOffer,
    TResult Function(PairChannelCommandDto_SendPairJoin value)? sendPairJoin,
    TResult Function(PairChannelCommandDto_ConnectPair value)? connectPair,
    TResult Function(PairChannelCommandDto_SendFrame value)? sendFrame,
    TResult Function(PairChannelCommandDto_ClosePair value)? closePair,
    TResult Function(PairChannelCommandDto_DropPair value)? dropPair,
    TResult Function(PairChannelCommandDto_PublishRingEvent value)?
        publishRingEvent,
    TResult Function(PairChannelCommandDto_LoadHistory value)? loadHistory,
    TResult Function(PairChannelCommandDto_StoreMessages value)? storeMessages,
    TResult Function(PairChannelCommandDto_SaveMlsState value)? saveMlsState,
    TResult Function(PairChannelCommandDto_SaveRingState value)? saveRingState,
    TResult Function(PairChannelCommandDto_RingJoined value)? ringJoined,
    TResult Function(PairChannelCommandDto_DeviceAdmitted value)?
        deviceAdmitted,
    TResult Function(PairChannelCommandDto_SiblingStealthLearned value)?
        siblingStealthLearned,
    TResult Function(PairChannelCommandDto_TransferComplete value)?
        transferComplete,
    TResult Function(PairChannelCommandDto_TransferFailed value)?
        transferFailed,
    TResult Function(PairChannelCommandDto_Log value)? log,
    required TResult orElse(),
  }) {
    if (sendPairOffer != null) {
      return sendPairOffer(this);
    }
    return orElse();
  }
}

abstract class PairChannelCommandDto_SendPairOffer
    extends PairChannelCommandDto {
  const factory PairChannelCommandDto_SendPairOffer(
          {required final String drawbridgeUrl,
          required final Uint8List token}) =
      _$PairChannelCommandDto_SendPairOfferImpl;
  const PairChannelCommandDto_SendPairOffer._() : super._();

  String get drawbridgeUrl;
  Uint8List get token;

  /// Create a copy of PairChannelCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$PairChannelCommandDto_SendPairOfferImplCopyWith<
          _$PairChannelCommandDto_SendPairOfferImpl>
      get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$PairChannelCommandDto_SendPairJoinImplCopyWith<$Res> {
  factory _$$PairChannelCommandDto_SendPairJoinImplCopyWith(
          _$PairChannelCommandDto_SendPairJoinImpl value,
          $Res Function(_$PairChannelCommandDto_SendPairJoinImpl) then) =
      __$$PairChannelCommandDto_SendPairJoinImplCopyWithImpl<$Res>;
  @useResult
  $Res call({String drawbridgeUrl, Uint8List token});
}

/// @nodoc
class __$$PairChannelCommandDto_SendPairJoinImplCopyWithImpl<$Res>
    extends _$PairChannelCommandDtoCopyWithImpl<$Res,
        _$PairChannelCommandDto_SendPairJoinImpl>
    implements _$$PairChannelCommandDto_SendPairJoinImplCopyWith<$Res> {
  __$$PairChannelCommandDto_SendPairJoinImplCopyWithImpl(
      _$PairChannelCommandDto_SendPairJoinImpl _value,
      $Res Function(_$PairChannelCommandDto_SendPairJoinImpl) _then)
      : super(_value, _then);

  /// Create a copy of PairChannelCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? drawbridgeUrl = null,
    Object? token = null,
  }) {
    return _then(_$PairChannelCommandDto_SendPairJoinImpl(
      drawbridgeUrl: null == drawbridgeUrl
          ? _value.drawbridgeUrl
          : drawbridgeUrl // ignore: cast_nullable_to_non_nullable
              as String,
      token: null == token
          ? _value.token
          : token // ignore: cast_nullable_to_non_nullable
              as Uint8List,
    ));
  }
}

/// @nodoc

class _$PairChannelCommandDto_SendPairJoinImpl
    extends PairChannelCommandDto_SendPairJoin {
  const _$PairChannelCommandDto_SendPairJoinImpl(
      {required this.drawbridgeUrl, required this.token})
      : super._();

  @override
  final String drawbridgeUrl;
  @override
  final Uint8List token;

  @override
  String toString() {
    return 'PairChannelCommandDto.sendPairJoin(drawbridgeUrl: $drawbridgeUrl, token: $token)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$PairChannelCommandDto_SendPairJoinImpl &&
            (identical(other.drawbridgeUrl, drawbridgeUrl) ||
                other.drawbridgeUrl == drawbridgeUrl) &&
            const DeepCollectionEquality().equals(other.token, token));
  }

  @override
  int get hashCode => Object.hash(
      runtimeType, drawbridgeUrl, const DeepCollectionEquality().hash(token));

  /// Create a copy of PairChannelCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$PairChannelCommandDto_SendPairJoinImplCopyWith<
          _$PairChannelCommandDto_SendPairJoinImpl>
      get copyWith => __$$PairChannelCommandDto_SendPairJoinImplCopyWithImpl<
          _$PairChannelCommandDto_SendPairJoinImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(String drawbridgeUrl, Uint8List token)
        sendPairOffer,
    required TResult Function(String drawbridgeUrl, Uint8List token)
        sendPairJoin,
    required TResult Function(String url, Uint8List token) connectPair,
    required TResult Function(Uint8List data) sendFrame,
    required TResult Function() closePair,
    required TResult Function() dropPair,
    required TResult Function(Uint8List tag, Uint8List ciphertext)
        publishRingEvent,
    required TResult Function(Uint8List token) loadHistory,
    required TResult Function(String convId, List<SyncMessageDto> messages)
        storeMessages,
    required TResult Function() saveMlsState,
    required TResult Function() saveRingState,
    required TResult Function(Uint8List ringId) ringJoined,
    required TResult Function(Uint8List ringId) deviceAdmitted,
    required TResult Function(Uint8List deviceId, Uint8List scanPubkey)
        siblingStealthLearned,
    required TResult Function(SyncTallyDto tally) transferComplete,
    required TResult Function(String detail, bool duringPairing) transferFailed,
    required TResult Function(String line) log,
  }) {
    return sendPairJoin(drawbridgeUrl, token);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(String drawbridgeUrl, Uint8List token)? sendPairOffer,
    TResult? Function(String drawbridgeUrl, Uint8List token)? sendPairJoin,
    TResult? Function(String url, Uint8List token)? connectPair,
    TResult? Function(Uint8List data)? sendFrame,
    TResult? Function()? closePair,
    TResult? Function()? dropPair,
    TResult? Function(Uint8List tag, Uint8List ciphertext)? publishRingEvent,
    TResult? Function(Uint8List token)? loadHistory,
    TResult? Function(String convId, List<SyncMessageDto> messages)?
        storeMessages,
    TResult? Function()? saveMlsState,
    TResult? Function()? saveRingState,
    TResult? Function(Uint8List ringId)? ringJoined,
    TResult? Function(Uint8List ringId)? deviceAdmitted,
    TResult? Function(Uint8List deviceId, Uint8List scanPubkey)?
        siblingStealthLearned,
    TResult? Function(SyncTallyDto tally)? transferComplete,
    TResult? Function(String detail, bool duringPairing)? transferFailed,
    TResult? Function(String line)? log,
  }) {
    return sendPairJoin?.call(drawbridgeUrl, token);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(String drawbridgeUrl, Uint8List token)? sendPairOffer,
    TResult Function(String drawbridgeUrl, Uint8List token)? sendPairJoin,
    TResult Function(String url, Uint8List token)? connectPair,
    TResult Function(Uint8List data)? sendFrame,
    TResult Function()? closePair,
    TResult Function()? dropPair,
    TResult Function(Uint8List tag, Uint8List ciphertext)? publishRingEvent,
    TResult Function(Uint8List token)? loadHistory,
    TResult Function(String convId, List<SyncMessageDto> messages)?
        storeMessages,
    TResult Function()? saveMlsState,
    TResult Function()? saveRingState,
    TResult Function(Uint8List ringId)? ringJoined,
    TResult Function(Uint8List ringId)? deviceAdmitted,
    TResult Function(Uint8List deviceId, Uint8List scanPubkey)?
        siblingStealthLearned,
    TResult Function(SyncTallyDto tally)? transferComplete,
    TResult Function(String detail, bool duringPairing)? transferFailed,
    TResult Function(String line)? log,
    required TResult orElse(),
  }) {
    if (sendPairJoin != null) {
      return sendPairJoin(drawbridgeUrl, token);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(PairChannelCommandDto_SendPairOffer value)
        sendPairOffer,
    required TResult Function(PairChannelCommandDto_SendPairJoin value)
        sendPairJoin,
    required TResult Function(PairChannelCommandDto_ConnectPair value)
        connectPair,
    required TResult Function(PairChannelCommandDto_SendFrame value) sendFrame,
    required TResult Function(PairChannelCommandDto_ClosePair value) closePair,
    required TResult Function(PairChannelCommandDto_DropPair value) dropPair,
    required TResult Function(PairChannelCommandDto_PublishRingEvent value)
        publishRingEvent,
    required TResult Function(PairChannelCommandDto_LoadHistory value)
        loadHistory,
    required TResult Function(PairChannelCommandDto_StoreMessages value)
        storeMessages,
    required TResult Function(PairChannelCommandDto_SaveMlsState value)
        saveMlsState,
    required TResult Function(PairChannelCommandDto_SaveRingState value)
        saveRingState,
    required TResult Function(PairChannelCommandDto_RingJoined value)
        ringJoined,
    required TResult Function(PairChannelCommandDto_DeviceAdmitted value)
        deviceAdmitted,
    required TResult Function(PairChannelCommandDto_SiblingStealthLearned value)
        siblingStealthLearned,
    required TResult Function(PairChannelCommandDto_TransferComplete value)
        transferComplete,
    required TResult Function(PairChannelCommandDto_TransferFailed value)
        transferFailed,
    required TResult Function(PairChannelCommandDto_Log value) log,
  }) {
    return sendPairJoin(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(PairChannelCommandDto_SendPairOffer value)? sendPairOffer,
    TResult? Function(PairChannelCommandDto_SendPairJoin value)? sendPairJoin,
    TResult? Function(PairChannelCommandDto_ConnectPair value)? connectPair,
    TResult? Function(PairChannelCommandDto_SendFrame value)? sendFrame,
    TResult? Function(PairChannelCommandDto_ClosePair value)? closePair,
    TResult? Function(PairChannelCommandDto_DropPair value)? dropPair,
    TResult? Function(PairChannelCommandDto_PublishRingEvent value)?
        publishRingEvent,
    TResult? Function(PairChannelCommandDto_LoadHistory value)? loadHistory,
    TResult? Function(PairChannelCommandDto_StoreMessages value)? storeMessages,
    TResult? Function(PairChannelCommandDto_SaveMlsState value)? saveMlsState,
    TResult? Function(PairChannelCommandDto_SaveRingState value)? saveRingState,
    TResult? Function(PairChannelCommandDto_RingJoined value)? ringJoined,
    TResult? Function(PairChannelCommandDto_DeviceAdmitted value)?
        deviceAdmitted,
    TResult? Function(PairChannelCommandDto_SiblingStealthLearned value)?
        siblingStealthLearned,
    TResult? Function(PairChannelCommandDto_TransferComplete value)?
        transferComplete,
    TResult? Function(PairChannelCommandDto_TransferFailed value)?
        transferFailed,
    TResult? Function(PairChannelCommandDto_Log value)? log,
  }) {
    return sendPairJoin?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(PairChannelCommandDto_SendPairOffer value)? sendPairOffer,
    TResult Function(PairChannelCommandDto_SendPairJoin value)? sendPairJoin,
    TResult Function(PairChannelCommandDto_ConnectPair value)? connectPair,
    TResult Function(PairChannelCommandDto_SendFrame value)? sendFrame,
    TResult Function(PairChannelCommandDto_ClosePair value)? closePair,
    TResult Function(PairChannelCommandDto_DropPair value)? dropPair,
    TResult Function(PairChannelCommandDto_PublishRingEvent value)?
        publishRingEvent,
    TResult Function(PairChannelCommandDto_LoadHistory value)? loadHistory,
    TResult Function(PairChannelCommandDto_StoreMessages value)? storeMessages,
    TResult Function(PairChannelCommandDto_SaveMlsState value)? saveMlsState,
    TResult Function(PairChannelCommandDto_SaveRingState value)? saveRingState,
    TResult Function(PairChannelCommandDto_RingJoined value)? ringJoined,
    TResult Function(PairChannelCommandDto_DeviceAdmitted value)?
        deviceAdmitted,
    TResult Function(PairChannelCommandDto_SiblingStealthLearned value)?
        siblingStealthLearned,
    TResult Function(PairChannelCommandDto_TransferComplete value)?
        transferComplete,
    TResult Function(PairChannelCommandDto_TransferFailed value)?
        transferFailed,
    TResult Function(PairChannelCommandDto_Log value)? log,
    required TResult orElse(),
  }) {
    if (sendPairJoin != null) {
      return sendPairJoin(this);
    }
    return orElse();
  }
}

abstract class PairChannelCommandDto_SendPairJoin
    extends PairChannelCommandDto {
  const factory PairChannelCommandDto_SendPairJoin(
          {required final String drawbridgeUrl,
          required final Uint8List token}) =
      _$PairChannelCommandDto_SendPairJoinImpl;
  const PairChannelCommandDto_SendPairJoin._() : super._();

  String get drawbridgeUrl;
  Uint8List get token;

  /// Create a copy of PairChannelCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$PairChannelCommandDto_SendPairJoinImplCopyWith<
          _$PairChannelCommandDto_SendPairJoinImpl>
      get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$PairChannelCommandDto_ConnectPairImplCopyWith<$Res> {
  factory _$$PairChannelCommandDto_ConnectPairImplCopyWith(
          _$PairChannelCommandDto_ConnectPairImpl value,
          $Res Function(_$PairChannelCommandDto_ConnectPairImpl) then) =
      __$$PairChannelCommandDto_ConnectPairImplCopyWithImpl<$Res>;
  @useResult
  $Res call({String url, Uint8List token});
}

/// @nodoc
class __$$PairChannelCommandDto_ConnectPairImplCopyWithImpl<$Res>
    extends _$PairChannelCommandDtoCopyWithImpl<$Res,
        _$PairChannelCommandDto_ConnectPairImpl>
    implements _$$PairChannelCommandDto_ConnectPairImplCopyWith<$Res> {
  __$$PairChannelCommandDto_ConnectPairImplCopyWithImpl(
      _$PairChannelCommandDto_ConnectPairImpl _value,
      $Res Function(_$PairChannelCommandDto_ConnectPairImpl) _then)
      : super(_value, _then);

  /// Create a copy of PairChannelCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? url = null,
    Object? token = null,
  }) {
    return _then(_$PairChannelCommandDto_ConnectPairImpl(
      url: null == url
          ? _value.url
          : url // ignore: cast_nullable_to_non_nullable
              as String,
      token: null == token
          ? _value.token
          : token // ignore: cast_nullable_to_non_nullable
              as Uint8List,
    ));
  }
}

/// @nodoc

class _$PairChannelCommandDto_ConnectPairImpl
    extends PairChannelCommandDto_ConnectPair {
  const _$PairChannelCommandDto_ConnectPairImpl(
      {required this.url, required this.token})
      : super._();

  @override
  final String url;
  @override
  final Uint8List token;

  @override
  String toString() {
    return 'PairChannelCommandDto.connectPair(url: $url, token: $token)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$PairChannelCommandDto_ConnectPairImpl &&
            (identical(other.url, url) || other.url == url) &&
            const DeepCollectionEquality().equals(other.token, token));
  }

  @override
  int get hashCode =>
      Object.hash(runtimeType, url, const DeepCollectionEquality().hash(token));

  /// Create a copy of PairChannelCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$PairChannelCommandDto_ConnectPairImplCopyWith<
          _$PairChannelCommandDto_ConnectPairImpl>
      get copyWith => __$$PairChannelCommandDto_ConnectPairImplCopyWithImpl<
          _$PairChannelCommandDto_ConnectPairImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(String drawbridgeUrl, Uint8List token)
        sendPairOffer,
    required TResult Function(String drawbridgeUrl, Uint8List token)
        sendPairJoin,
    required TResult Function(String url, Uint8List token) connectPair,
    required TResult Function(Uint8List data) sendFrame,
    required TResult Function() closePair,
    required TResult Function() dropPair,
    required TResult Function(Uint8List tag, Uint8List ciphertext)
        publishRingEvent,
    required TResult Function(Uint8List token) loadHistory,
    required TResult Function(String convId, List<SyncMessageDto> messages)
        storeMessages,
    required TResult Function() saveMlsState,
    required TResult Function() saveRingState,
    required TResult Function(Uint8List ringId) ringJoined,
    required TResult Function(Uint8List ringId) deviceAdmitted,
    required TResult Function(Uint8List deviceId, Uint8List scanPubkey)
        siblingStealthLearned,
    required TResult Function(SyncTallyDto tally) transferComplete,
    required TResult Function(String detail, bool duringPairing) transferFailed,
    required TResult Function(String line) log,
  }) {
    return connectPair(url, token);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(String drawbridgeUrl, Uint8List token)? sendPairOffer,
    TResult? Function(String drawbridgeUrl, Uint8List token)? sendPairJoin,
    TResult? Function(String url, Uint8List token)? connectPair,
    TResult? Function(Uint8List data)? sendFrame,
    TResult? Function()? closePair,
    TResult? Function()? dropPair,
    TResult? Function(Uint8List tag, Uint8List ciphertext)? publishRingEvent,
    TResult? Function(Uint8List token)? loadHistory,
    TResult? Function(String convId, List<SyncMessageDto> messages)?
        storeMessages,
    TResult? Function()? saveMlsState,
    TResult? Function()? saveRingState,
    TResult? Function(Uint8List ringId)? ringJoined,
    TResult? Function(Uint8List ringId)? deviceAdmitted,
    TResult? Function(Uint8List deviceId, Uint8List scanPubkey)?
        siblingStealthLearned,
    TResult? Function(SyncTallyDto tally)? transferComplete,
    TResult? Function(String detail, bool duringPairing)? transferFailed,
    TResult? Function(String line)? log,
  }) {
    return connectPair?.call(url, token);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(String drawbridgeUrl, Uint8List token)? sendPairOffer,
    TResult Function(String drawbridgeUrl, Uint8List token)? sendPairJoin,
    TResult Function(String url, Uint8List token)? connectPair,
    TResult Function(Uint8List data)? sendFrame,
    TResult Function()? closePair,
    TResult Function()? dropPair,
    TResult Function(Uint8List tag, Uint8List ciphertext)? publishRingEvent,
    TResult Function(Uint8List token)? loadHistory,
    TResult Function(String convId, List<SyncMessageDto> messages)?
        storeMessages,
    TResult Function()? saveMlsState,
    TResult Function()? saveRingState,
    TResult Function(Uint8List ringId)? ringJoined,
    TResult Function(Uint8List ringId)? deviceAdmitted,
    TResult Function(Uint8List deviceId, Uint8List scanPubkey)?
        siblingStealthLearned,
    TResult Function(SyncTallyDto tally)? transferComplete,
    TResult Function(String detail, bool duringPairing)? transferFailed,
    TResult Function(String line)? log,
    required TResult orElse(),
  }) {
    if (connectPair != null) {
      return connectPair(url, token);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(PairChannelCommandDto_SendPairOffer value)
        sendPairOffer,
    required TResult Function(PairChannelCommandDto_SendPairJoin value)
        sendPairJoin,
    required TResult Function(PairChannelCommandDto_ConnectPair value)
        connectPair,
    required TResult Function(PairChannelCommandDto_SendFrame value) sendFrame,
    required TResult Function(PairChannelCommandDto_ClosePair value) closePair,
    required TResult Function(PairChannelCommandDto_DropPair value) dropPair,
    required TResult Function(PairChannelCommandDto_PublishRingEvent value)
        publishRingEvent,
    required TResult Function(PairChannelCommandDto_LoadHistory value)
        loadHistory,
    required TResult Function(PairChannelCommandDto_StoreMessages value)
        storeMessages,
    required TResult Function(PairChannelCommandDto_SaveMlsState value)
        saveMlsState,
    required TResult Function(PairChannelCommandDto_SaveRingState value)
        saveRingState,
    required TResult Function(PairChannelCommandDto_RingJoined value)
        ringJoined,
    required TResult Function(PairChannelCommandDto_DeviceAdmitted value)
        deviceAdmitted,
    required TResult Function(PairChannelCommandDto_SiblingStealthLearned value)
        siblingStealthLearned,
    required TResult Function(PairChannelCommandDto_TransferComplete value)
        transferComplete,
    required TResult Function(PairChannelCommandDto_TransferFailed value)
        transferFailed,
    required TResult Function(PairChannelCommandDto_Log value) log,
  }) {
    return connectPair(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(PairChannelCommandDto_SendPairOffer value)? sendPairOffer,
    TResult? Function(PairChannelCommandDto_SendPairJoin value)? sendPairJoin,
    TResult? Function(PairChannelCommandDto_ConnectPair value)? connectPair,
    TResult? Function(PairChannelCommandDto_SendFrame value)? sendFrame,
    TResult? Function(PairChannelCommandDto_ClosePair value)? closePair,
    TResult? Function(PairChannelCommandDto_DropPair value)? dropPair,
    TResult? Function(PairChannelCommandDto_PublishRingEvent value)?
        publishRingEvent,
    TResult? Function(PairChannelCommandDto_LoadHistory value)? loadHistory,
    TResult? Function(PairChannelCommandDto_StoreMessages value)? storeMessages,
    TResult? Function(PairChannelCommandDto_SaveMlsState value)? saveMlsState,
    TResult? Function(PairChannelCommandDto_SaveRingState value)? saveRingState,
    TResult? Function(PairChannelCommandDto_RingJoined value)? ringJoined,
    TResult? Function(PairChannelCommandDto_DeviceAdmitted value)?
        deviceAdmitted,
    TResult? Function(PairChannelCommandDto_SiblingStealthLearned value)?
        siblingStealthLearned,
    TResult? Function(PairChannelCommandDto_TransferComplete value)?
        transferComplete,
    TResult? Function(PairChannelCommandDto_TransferFailed value)?
        transferFailed,
    TResult? Function(PairChannelCommandDto_Log value)? log,
  }) {
    return connectPair?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(PairChannelCommandDto_SendPairOffer value)? sendPairOffer,
    TResult Function(PairChannelCommandDto_SendPairJoin value)? sendPairJoin,
    TResult Function(PairChannelCommandDto_ConnectPair value)? connectPair,
    TResult Function(PairChannelCommandDto_SendFrame value)? sendFrame,
    TResult Function(PairChannelCommandDto_ClosePair value)? closePair,
    TResult Function(PairChannelCommandDto_DropPair value)? dropPair,
    TResult Function(PairChannelCommandDto_PublishRingEvent value)?
        publishRingEvent,
    TResult Function(PairChannelCommandDto_LoadHistory value)? loadHistory,
    TResult Function(PairChannelCommandDto_StoreMessages value)? storeMessages,
    TResult Function(PairChannelCommandDto_SaveMlsState value)? saveMlsState,
    TResult Function(PairChannelCommandDto_SaveRingState value)? saveRingState,
    TResult Function(PairChannelCommandDto_RingJoined value)? ringJoined,
    TResult Function(PairChannelCommandDto_DeviceAdmitted value)?
        deviceAdmitted,
    TResult Function(PairChannelCommandDto_SiblingStealthLearned value)?
        siblingStealthLearned,
    TResult Function(PairChannelCommandDto_TransferComplete value)?
        transferComplete,
    TResult Function(PairChannelCommandDto_TransferFailed value)?
        transferFailed,
    TResult Function(PairChannelCommandDto_Log value)? log,
    required TResult orElse(),
  }) {
    if (connectPair != null) {
      return connectPair(this);
    }
    return orElse();
  }
}

abstract class PairChannelCommandDto_ConnectPair extends PairChannelCommandDto {
  const factory PairChannelCommandDto_ConnectPair(
          {required final String url, required final Uint8List token}) =
      _$PairChannelCommandDto_ConnectPairImpl;
  const PairChannelCommandDto_ConnectPair._() : super._();

  String get url;
  Uint8List get token;

  /// Create a copy of PairChannelCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$PairChannelCommandDto_ConnectPairImplCopyWith<
          _$PairChannelCommandDto_ConnectPairImpl>
      get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$PairChannelCommandDto_SendFrameImplCopyWith<$Res> {
  factory _$$PairChannelCommandDto_SendFrameImplCopyWith(
          _$PairChannelCommandDto_SendFrameImpl value,
          $Res Function(_$PairChannelCommandDto_SendFrameImpl) then) =
      __$$PairChannelCommandDto_SendFrameImplCopyWithImpl<$Res>;
  @useResult
  $Res call({Uint8List data});
}

/// @nodoc
class __$$PairChannelCommandDto_SendFrameImplCopyWithImpl<$Res>
    extends _$PairChannelCommandDtoCopyWithImpl<$Res,
        _$PairChannelCommandDto_SendFrameImpl>
    implements _$$PairChannelCommandDto_SendFrameImplCopyWith<$Res> {
  __$$PairChannelCommandDto_SendFrameImplCopyWithImpl(
      _$PairChannelCommandDto_SendFrameImpl _value,
      $Res Function(_$PairChannelCommandDto_SendFrameImpl) _then)
      : super(_value, _then);

  /// Create a copy of PairChannelCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? data = null,
  }) {
    return _then(_$PairChannelCommandDto_SendFrameImpl(
      data: null == data
          ? _value.data
          : data // ignore: cast_nullable_to_non_nullable
              as Uint8List,
    ));
  }
}

/// @nodoc

class _$PairChannelCommandDto_SendFrameImpl
    extends PairChannelCommandDto_SendFrame {
  const _$PairChannelCommandDto_SendFrameImpl({required this.data}) : super._();

  @override
  final Uint8List data;

  @override
  String toString() {
    return 'PairChannelCommandDto.sendFrame(data: $data)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$PairChannelCommandDto_SendFrameImpl &&
            const DeepCollectionEquality().equals(other.data, data));
  }

  @override
  int get hashCode =>
      Object.hash(runtimeType, const DeepCollectionEquality().hash(data));

  /// Create a copy of PairChannelCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$PairChannelCommandDto_SendFrameImplCopyWith<
          _$PairChannelCommandDto_SendFrameImpl>
      get copyWith => __$$PairChannelCommandDto_SendFrameImplCopyWithImpl<
          _$PairChannelCommandDto_SendFrameImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(String drawbridgeUrl, Uint8List token)
        sendPairOffer,
    required TResult Function(String drawbridgeUrl, Uint8List token)
        sendPairJoin,
    required TResult Function(String url, Uint8List token) connectPair,
    required TResult Function(Uint8List data) sendFrame,
    required TResult Function() closePair,
    required TResult Function() dropPair,
    required TResult Function(Uint8List tag, Uint8List ciphertext)
        publishRingEvent,
    required TResult Function(Uint8List token) loadHistory,
    required TResult Function(String convId, List<SyncMessageDto> messages)
        storeMessages,
    required TResult Function() saveMlsState,
    required TResult Function() saveRingState,
    required TResult Function(Uint8List ringId) ringJoined,
    required TResult Function(Uint8List ringId) deviceAdmitted,
    required TResult Function(Uint8List deviceId, Uint8List scanPubkey)
        siblingStealthLearned,
    required TResult Function(SyncTallyDto tally) transferComplete,
    required TResult Function(String detail, bool duringPairing) transferFailed,
    required TResult Function(String line) log,
  }) {
    return sendFrame(data);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(String drawbridgeUrl, Uint8List token)? sendPairOffer,
    TResult? Function(String drawbridgeUrl, Uint8List token)? sendPairJoin,
    TResult? Function(String url, Uint8List token)? connectPair,
    TResult? Function(Uint8List data)? sendFrame,
    TResult? Function()? closePair,
    TResult? Function()? dropPair,
    TResult? Function(Uint8List tag, Uint8List ciphertext)? publishRingEvent,
    TResult? Function(Uint8List token)? loadHistory,
    TResult? Function(String convId, List<SyncMessageDto> messages)?
        storeMessages,
    TResult? Function()? saveMlsState,
    TResult? Function()? saveRingState,
    TResult? Function(Uint8List ringId)? ringJoined,
    TResult? Function(Uint8List ringId)? deviceAdmitted,
    TResult? Function(Uint8List deviceId, Uint8List scanPubkey)?
        siblingStealthLearned,
    TResult? Function(SyncTallyDto tally)? transferComplete,
    TResult? Function(String detail, bool duringPairing)? transferFailed,
    TResult? Function(String line)? log,
  }) {
    return sendFrame?.call(data);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(String drawbridgeUrl, Uint8List token)? sendPairOffer,
    TResult Function(String drawbridgeUrl, Uint8List token)? sendPairJoin,
    TResult Function(String url, Uint8List token)? connectPair,
    TResult Function(Uint8List data)? sendFrame,
    TResult Function()? closePair,
    TResult Function()? dropPair,
    TResult Function(Uint8List tag, Uint8List ciphertext)? publishRingEvent,
    TResult Function(Uint8List token)? loadHistory,
    TResult Function(String convId, List<SyncMessageDto> messages)?
        storeMessages,
    TResult Function()? saveMlsState,
    TResult Function()? saveRingState,
    TResult Function(Uint8List ringId)? ringJoined,
    TResult Function(Uint8List ringId)? deviceAdmitted,
    TResult Function(Uint8List deviceId, Uint8List scanPubkey)?
        siblingStealthLearned,
    TResult Function(SyncTallyDto tally)? transferComplete,
    TResult Function(String detail, bool duringPairing)? transferFailed,
    TResult Function(String line)? log,
    required TResult orElse(),
  }) {
    if (sendFrame != null) {
      return sendFrame(data);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(PairChannelCommandDto_SendPairOffer value)
        sendPairOffer,
    required TResult Function(PairChannelCommandDto_SendPairJoin value)
        sendPairJoin,
    required TResult Function(PairChannelCommandDto_ConnectPair value)
        connectPair,
    required TResult Function(PairChannelCommandDto_SendFrame value) sendFrame,
    required TResult Function(PairChannelCommandDto_ClosePair value) closePair,
    required TResult Function(PairChannelCommandDto_DropPair value) dropPair,
    required TResult Function(PairChannelCommandDto_PublishRingEvent value)
        publishRingEvent,
    required TResult Function(PairChannelCommandDto_LoadHistory value)
        loadHistory,
    required TResult Function(PairChannelCommandDto_StoreMessages value)
        storeMessages,
    required TResult Function(PairChannelCommandDto_SaveMlsState value)
        saveMlsState,
    required TResult Function(PairChannelCommandDto_SaveRingState value)
        saveRingState,
    required TResult Function(PairChannelCommandDto_RingJoined value)
        ringJoined,
    required TResult Function(PairChannelCommandDto_DeviceAdmitted value)
        deviceAdmitted,
    required TResult Function(PairChannelCommandDto_SiblingStealthLearned value)
        siblingStealthLearned,
    required TResult Function(PairChannelCommandDto_TransferComplete value)
        transferComplete,
    required TResult Function(PairChannelCommandDto_TransferFailed value)
        transferFailed,
    required TResult Function(PairChannelCommandDto_Log value) log,
  }) {
    return sendFrame(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(PairChannelCommandDto_SendPairOffer value)? sendPairOffer,
    TResult? Function(PairChannelCommandDto_SendPairJoin value)? sendPairJoin,
    TResult? Function(PairChannelCommandDto_ConnectPair value)? connectPair,
    TResult? Function(PairChannelCommandDto_SendFrame value)? sendFrame,
    TResult? Function(PairChannelCommandDto_ClosePair value)? closePair,
    TResult? Function(PairChannelCommandDto_DropPair value)? dropPair,
    TResult? Function(PairChannelCommandDto_PublishRingEvent value)?
        publishRingEvent,
    TResult? Function(PairChannelCommandDto_LoadHistory value)? loadHistory,
    TResult? Function(PairChannelCommandDto_StoreMessages value)? storeMessages,
    TResult? Function(PairChannelCommandDto_SaveMlsState value)? saveMlsState,
    TResult? Function(PairChannelCommandDto_SaveRingState value)? saveRingState,
    TResult? Function(PairChannelCommandDto_RingJoined value)? ringJoined,
    TResult? Function(PairChannelCommandDto_DeviceAdmitted value)?
        deviceAdmitted,
    TResult? Function(PairChannelCommandDto_SiblingStealthLearned value)?
        siblingStealthLearned,
    TResult? Function(PairChannelCommandDto_TransferComplete value)?
        transferComplete,
    TResult? Function(PairChannelCommandDto_TransferFailed value)?
        transferFailed,
    TResult? Function(PairChannelCommandDto_Log value)? log,
  }) {
    return sendFrame?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(PairChannelCommandDto_SendPairOffer value)? sendPairOffer,
    TResult Function(PairChannelCommandDto_SendPairJoin value)? sendPairJoin,
    TResult Function(PairChannelCommandDto_ConnectPair value)? connectPair,
    TResult Function(PairChannelCommandDto_SendFrame value)? sendFrame,
    TResult Function(PairChannelCommandDto_ClosePair value)? closePair,
    TResult Function(PairChannelCommandDto_DropPair value)? dropPair,
    TResult Function(PairChannelCommandDto_PublishRingEvent value)?
        publishRingEvent,
    TResult Function(PairChannelCommandDto_LoadHistory value)? loadHistory,
    TResult Function(PairChannelCommandDto_StoreMessages value)? storeMessages,
    TResult Function(PairChannelCommandDto_SaveMlsState value)? saveMlsState,
    TResult Function(PairChannelCommandDto_SaveRingState value)? saveRingState,
    TResult Function(PairChannelCommandDto_RingJoined value)? ringJoined,
    TResult Function(PairChannelCommandDto_DeviceAdmitted value)?
        deviceAdmitted,
    TResult Function(PairChannelCommandDto_SiblingStealthLearned value)?
        siblingStealthLearned,
    TResult Function(PairChannelCommandDto_TransferComplete value)?
        transferComplete,
    TResult Function(PairChannelCommandDto_TransferFailed value)?
        transferFailed,
    TResult Function(PairChannelCommandDto_Log value)? log,
    required TResult orElse(),
  }) {
    if (sendFrame != null) {
      return sendFrame(this);
    }
    return orElse();
  }
}

abstract class PairChannelCommandDto_SendFrame extends PairChannelCommandDto {
  const factory PairChannelCommandDto_SendFrame(
      {required final Uint8List data}) = _$PairChannelCommandDto_SendFrameImpl;
  const PairChannelCommandDto_SendFrame._() : super._();

  Uint8List get data;

  /// Create a copy of PairChannelCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$PairChannelCommandDto_SendFrameImplCopyWith<
          _$PairChannelCommandDto_SendFrameImpl>
      get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$PairChannelCommandDto_ClosePairImplCopyWith<$Res> {
  factory _$$PairChannelCommandDto_ClosePairImplCopyWith(
          _$PairChannelCommandDto_ClosePairImpl value,
          $Res Function(_$PairChannelCommandDto_ClosePairImpl) then) =
      __$$PairChannelCommandDto_ClosePairImplCopyWithImpl<$Res>;
}

/// @nodoc
class __$$PairChannelCommandDto_ClosePairImplCopyWithImpl<$Res>
    extends _$PairChannelCommandDtoCopyWithImpl<$Res,
        _$PairChannelCommandDto_ClosePairImpl>
    implements _$$PairChannelCommandDto_ClosePairImplCopyWith<$Res> {
  __$$PairChannelCommandDto_ClosePairImplCopyWithImpl(
      _$PairChannelCommandDto_ClosePairImpl _value,
      $Res Function(_$PairChannelCommandDto_ClosePairImpl) _then)
      : super(_value, _then);

  /// Create a copy of PairChannelCommandDto
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc

class _$PairChannelCommandDto_ClosePairImpl
    extends PairChannelCommandDto_ClosePair {
  const _$PairChannelCommandDto_ClosePairImpl() : super._();

  @override
  String toString() {
    return 'PairChannelCommandDto.closePair()';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$PairChannelCommandDto_ClosePairImpl);
  }

  @override
  int get hashCode => runtimeType.hashCode;

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(String drawbridgeUrl, Uint8List token)
        sendPairOffer,
    required TResult Function(String drawbridgeUrl, Uint8List token)
        sendPairJoin,
    required TResult Function(String url, Uint8List token) connectPair,
    required TResult Function(Uint8List data) sendFrame,
    required TResult Function() closePair,
    required TResult Function() dropPair,
    required TResult Function(Uint8List tag, Uint8List ciphertext)
        publishRingEvent,
    required TResult Function(Uint8List token) loadHistory,
    required TResult Function(String convId, List<SyncMessageDto> messages)
        storeMessages,
    required TResult Function() saveMlsState,
    required TResult Function() saveRingState,
    required TResult Function(Uint8List ringId) ringJoined,
    required TResult Function(Uint8List ringId) deviceAdmitted,
    required TResult Function(Uint8List deviceId, Uint8List scanPubkey)
        siblingStealthLearned,
    required TResult Function(SyncTallyDto tally) transferComplete,
    required TResult Function(String detail, bool duringPairing) transferFailed,
    required TResult Function(String line) log,
  }) {
    return closePair();
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(String drawbridgeUrl, Uint8List token)? sendPairOffer,
    TResult? Function(String drawbridgeUrl, Uint8List token)? sendPairJoin,
    TResult? Function(String url, Uint8List token)? connectPair,
    TResult? Function(Uint8List data)? sendFrame,
    TResult? Function()? closePair,
    TResult? Function()? dropPair,
    TResult? Function(Uint8List tag, Uint8List ciphertext)? publishRingEvent,
    TResult? Function(Uint8List token)? loadHistory,
    TResult? Function(String convId, List<SyncMessageDto> messages)?
        storeMessages,
    TResult? Function()? saveMlsState,
    TResult? Function()? saveRingState,
    TResult? Function(Uint8List ringId)? ringJoined,
    TResult? Function(Uint8List ringId)? deviceAdmitted,
    TResult? Function(Uint8List deviceId, Uint8List scanPubkey)?
        siblingStealthLearned,
    TResult? Function(SyncTallyDto tally)? transferComplete,
    TResult? Function(String detail, bool duringPairing)? transferFailed,
    TResult? Function(String line)? log,
  }) {
    return closePair?.call();
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(String drawbridgeUrl, Uint8List token)? sendPairOffer,
    TResult Function(String drawbridgeUrl, Uint8List token)? sendPairJoin,
    TResult Function(String url, Uint8List token)? connectPair,
    TResult Function(Uint8List data)? sendFrame,
    TResult Function()? closePair,
    TResult Function()? dropPair,
    TResult Function(Uint8List tag, Uint8List ciphertext)? publishRingEvent,
    TResult Function(Uint8List token)? loadHistory,
    TResult Function(String convId, List<SyncMessageDto> messages)?
        storeMessages,
    TResult Function()? saveMlsState,
    TResult Function()? saveRingState,
    TResult Function(Uint8List ringId)? ringJoined,
    TResult Function(Uint8List ringId)? deviceAdmitted,
    TResult Function(Uint8List deviceId, Uint8List scanPubkey)?
        siblingStealthLearned,
    TResult Function(SyncTallyDto tally)? transferComplete,
    TResult Function(String detail, bool duringPairing)? transferFailed,
    TResult Function(String line)? log,
    required TResult orElse(),
  }) {
    if (closePair != null) {
      return closePair();
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(PairChannelCommandDto_SendPairOffer value)
        sendPairOffer,
    required TResult Function(PairChannelCommandDto_SendPairJoin value)
        sendPairJoin,
    required TResult Function(PairChannelCommandDto_ConnectPair value)
        connectPair,
    required TResult Function(PairChannelCommandDto_SendFrame value) sendFrame,
    required TResult Function(PairChannelCommandDto_ClosePair value) closePair,
    required TResult Function(PairChannelCommandDto_DropPair value) dropPair,
    required TResult Function(PairChannelCommandDto_PublishRingEvent value)
        publishRingEvent,
    required TResult Function(PairChannelCommandDto_LoadHistory value)
        loadHistory,
    required TResult Function(PairChannelCommandDto_StoreMessages value)
        storeMessages,
    required TResult Function(PairChannelCommandDto_SaveMlsState value)
        saveMlsState,
    required TResult Function(PairChannelCommandDto_SaveRingState value)
        saveRingState,
    required TResult Function(PairChannelCommandDto_RingJoined value)
        ringJoined,
    required TResult Function(PairChannelCommandDto_DeviceAdmitted value)
        deviceAdmitted,
    required TResult Function(PairChannelCommandDto_SiblingStealthLearned value)
        siblingStealthLearned,
    required TResult Function(PairChannelCommandDto_TransferComplete value)
        transferComplete,
    required TResult Function(PairChannelCommandDto_TransferFailed value)
        transferFailed,
    required TResult Function(PairChannelCommandDto_Log value) log,
  }) {
    return closePair(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(PairChannelCommandDto_SendPairOffer value)? sendPairOffer,
    TResult? Function(PairChannelCommandDto_SendPairJoin value)? sendPairJoin,
    TResult? Function(PairChannelCommandDto_ConnectPair value)? connectPair,
    TResult? Function(PairChannelCommandDto_SendFrame value)? sendFrame,
    TResult? Function(PairChannelCommandDto_ClosePair value)? closePair,
    TResult? Function(PairChannelCommandDto_DropPair value)? dropPair,
    TResult? Function(PairChannelCommandDto_PublishRingEvent value)?
        publishRingEvent,
    TResult? Function(PairChannelCommandDto_LoadHistory value)? loadHistory,
    TResult? Function(PairChannelCommandDto_StoreMessages value)? storeMessages,
    TResult? Function(PairChannelCommandDto_SaveMlsState value)? saveMlsState,
    TResult? Function(PairChannelCommandDto_SaveRingState value)? saveRingState,
    TResult? Function(PairChannelCommandDto_RingJoined value)? ringJoined,
    TResult? Function(PairChannelCommandDto_DeviceAdmitted value)?
        deviceAdmitted,
    TResult? Function(PairChannelCommandDto_SiblingStealthLearned value)?
        siblingStealthLearned,
    TResult? Function(PairChannelCommandDto_TransferComplete value)?
        transferComplete,
    TResult? Function(PairChannelCommandDto_TransferFailed value)?
        transferFailed,
    TResult? Function(PairChannelCommandDto_Log value)? log,
  }) {
    return closePair?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(PairChannelCommandDto_SendPairOffer value)? sendPairOffer,
    TResult Function(PairChannelCommandDto_SendPairJoin value)? sendPairJoin,
    TResult Function(PairChannelCommandDto_ConnectPair value)? connectPair,
    TResult Function(PairChannelCommandDto_SendFrame value)? sendFrame,
    TResult Function(PairChannelCommandDto_ClosePair value)? closePair,
    TResult Function(PairChannelCommandDto_DropPair value)? dropPair,
    TResult Function(PairChannelCommandDto_PublishRingEvent value)?
        publishRingEvent,
    TResult Function(PairChannelCommandDto_LoadHistory value)? loadHistory,
    TResult Function(PairChannelCommandDto_StoreMessages value)? storeMessages,
    TResult Function(PairChannelCommandDto_SaveMlsState value)? saveMlsState,
    TResult Function(PairChannelCommandDto_SaveRingState value)? saveRingState,
    TResult Function(PairChannelCommandDto_RingJoined value)? ringJoined,
    TResult Function(PairChannelCommandDto_DeviceAdmitted value)?
        deviceAdmitted,
    TResult Function(PairChannelCommandDto_SiblingStealthLearned value)?
        siblingStealthLearned,
    TResult Function(PairChannelCommandDto_TransferComplete value)?
        transferComplete,
    TResult Function(PairChannelCommandDto_TransferFailed value)?
        transferFailed,
    TResult Function(PairChannelCommandDto_Log value)? log,
    required TResult orElse(),
  }) {
    if (closePair != null) {
      return closePair(this);
    }
    return orElse();
  }
}

abstract class PairChannelCommandDto_ClosePair extends PairChannelCommandDto {
  const factory PairChannelCommandDto_ClosePair() =
      _$PairChannelCommandDto_ClosePairImpl;
  const PairChannelCommandDto_ClosePair._() : super._();
}

/// @nodoc
abstract class _$$PairChannelCommandDto_DropPairImplCopyWith<$Res> {
  factory _$$PairChannelCommandDto_DropPairImplCopyWith(
          _$PairChannelCommandDto_DropPairImpl value,
          $Res Function(_$PairChannelCommandDto_DropPairImpl) then) =
      __$$PairChannelCommandDto_DropPairImplCopyWithImpl<$Res>;
}

/// @nodoc
class __$$PairChannelCommandDto_DropPairImplCopyWithImpl<$Res>
    extends _$PairChannelCommandDtoCopyWithImpl<$Res,
        _$PairChannelCommandDto_DropPairImpl>
    implements _$$PairChannelCommandDto_DropPairImplCopyWith<$Res> {
  __$$PairChannelCommandDto_DropPairImplCopyWithImpl(
      _$PairChannelCommandDto_DropPairImpl _value,
      $Res Function(_$PairChannelCommandDto_DropPairImpl) _then)
      : super(_value, _then);

  /// Create a copy of PairChannelCommandDto
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc

class _$PairChannelCommandDto_DropPairImpl
    extends PairChannelCommandDto_DropPair {
  const _$PairChannelCommandDto_DropPairImpl() : super._();

  @override
  String toString() {
    return 'PairChannelCommandDto.dropPair()';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$PairChannelCommandDto_DropPairImpl);
  }

  @override
  int get hashCode => runtimeType.hashCode;

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(String drawbridgeUrl, Uint8List token)
        sendPairOffer,
    required TResult Function(String drawbridgeUrl, Uint8List token)
        sendPairJoin,
    required TResult Function(String url, Uint8List token) connectPair,
    required TResult Function(Uint8List data) sendFrame,
    required TResult Function() closePair,
    required TResult Function() dropPair,
    required TResult Function(Uint8List tag, Uint8List ciphertext)
        publishRingEvent,
    required TResult Function(Uint8List token) loadHistory,
    required TResult Function(String convId, List<SyncMessageDto> messages)
        storeMessages,
    required TResult Function() saveMlsState,
    required TResult Function() saveRingState,
    required TResult Function(Uint8List ringId) ringJoined,
    required TResult Function(Uint8List ringId) deviceAdmitted,
    required TResult Function(Uint8List deviceId, Uint8List scanPubkey)
        siblingStealthLearned,
    required TResult Function(SyncTallyDto tally) transferComplete,
    required TResult Function(String detail, bool duringPairing) transferFailed,
    required TResult Function(String line) log,
  }) {
    return dropPair();
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(String drawbridgeUrl, Uint8List token)? sendPairOffer,
    TResult? Function(String drawbridgeUrl, Uint8List token)? sendPairJoin,
    TResult? Function(String url, Uint8List token)? connectPair,
    TResult? Function(Uint8List data)? sendFrame,
    TResult? Function()? closePair,
    TResult? Function()? dropPair,
    TResult? Function(Uint8List tag, Uint8List ciphertext)? publishRingEvent,
    TResult? Function(Uint8List token)? loadHistory,
    TResult? Function(String convId, List<SyncMessageDto> messages)?
        storeMessages,
    TResult? Function()? saveMlsState,
    TResult? Function()? saveRingState,
    TResult? Function(Uint8List ringId)? ringJoined,
    TResult? Function(Uint8List ringId)? deviceAdmitted,
    TResult? Function(Uint8List deviceId, Uint8List scanPubkey)?
        siblingStealthLearned,
    TResult? Function(SyncTallyDto tally)? transferComplete,
    TResult? Function(String detail, bool duringPairing)? transferFailed,
    TResult? Function(String line)? log,
  }) {
    return dropPair?.call();
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(String drawbridgeUrl, Uint8List token)? sendPairOffer,
    TResult Function(String drawbridgeUrl, Uint8List token)? sendPairJoin,
    TResult Function(String url, Uint8List token)? connectPair,
    TResult Function(Uint8List data)? sendFrame,
    TResult Function()? closePair,
    TResult Function()? dropPair,
    TResult Function(Uint8List tag, Uint8List ciphertext)? publishRingEvent,
    TResult Function(Uint8List token)? loadHistory,
    TResult Function(String convId, List<SyncMessageDto> messages)?
        storeMessages,
    TResult Function()? saveMlsState,
    TResult Function()? saveRingState,
    TResult Function(Uint8List ringId)? ringJoined,
    TResult Function(Uint8List ringId)? deviceAdmitted,
    TResult Function(Uint8List deviceId, Uint8List scanPubkey)?
        siblingStealthLearned,
    TResult Function(SyncTallyDto tally)? transferComplete,
    TResult Function(String detail, bool duringPairing)? transferFailed,
    TResult Function(String line)? log,
    required TResult orElse(),
  }) {
    if (dropPair != null) {
      return dropPair();
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(PairChannelCommandDto_SendPairOffer value)
        sendPairOffer,
    required TResult Function(PairChannelCommandDto_SendPairJoin value)
        sendPairJoin,
    required TResult Function(PairChannelCommandDto_ConnectPair value)
        connectPair,
    required TResult Function(PairChannelCommandDto_SendFrame value) sendFrame,
    required TResult Function(PairChannelCommandDto_ClosePair value) closePair,
    required TResult Function(PairChannelCommandDto_DropPair value) dropPair,
    required TResult Function(PairChannelCommandDto_PublishRingEvent value)
        publishRingEvent,
    required TResult Function(PairChannelCommandDto_LoadHistory value)
        loadHistory,
    required TResult Function(PairChannelCommandDto_StoreMessages value)
        storeMessages,
    required TResult Function(PairChannelCommandDto_SaveMlsState value)
        saveMlsState,
    required TResult Function(PairChannelCommandDto_SaveRingState value)
        saveRingState,
    required TResult Function(PairChannelCommandDto_RingJoined value)
        ringJoined,
    required TResult Function(PairChannelCommandDto_DeviceAdmitted value)
        deviceAdmitted,
    required TResult Function(PairChannelCommandDto_SiblingStealthLearned value)
        siblingStealthLearned,
    required TResult Function(PairChannelCommandDto_TransferComplete value)
        transferComplete,
    required TResult Function(PairChannelCommandDto_TransferFailed value)
        transferFailed,
    required TResult Function(PairChannelCommandDto_Log value) log,
  }) {
    return dropPair(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(PairChannelCommandDto_SendPairOffer value)? sendPairOffer,
    TResult? Function(PairChannelCommandDto_SendPairJoin value)? sendPairJoin,
    TResult? Function(PairChannelCommandDto_ConnectPair value)? connectPair,
    TResult? Function(PairChannelCommandDto_SendFrame value)? sendFrame,
    TResult? Function(PairChannelCommandDto_ClosePair value)? closePair,
    TResult? Function(PairChannelCommandDto_DropPair value)? dropPair,
    TResult? Function(PairChannelCommandDto_PublishRingEvent value)?
        publishRingEvent,
    TResult? Function(PairChannelCommandDto_LoadHistory value)? loadHistory,
    TResult? Function(PairChannelCommandDto_StoreMessages value)? storeMessages,
    TResult? Function(PairChannelCommandDto_SaveMlsState value)? saveMlsState,
    TResult? Function(PairChannelCommandDto_SaveRingState value)? saveRingState,
    TResult? Function(PairChannelCommandDto_RingJoined value)? ringJoined,
    TResult? Function(PairChannelCommandDto_DeviceAdmitted value)?
        deviceAdmitted,
    TResult? Function(PairChannelCommandDto_SiblingStealthLearned value)?
        siblingStealthLearned,
    TResult? Function(PairChannelCommandDto_TransferComplete value)?
        transferComplete,
    TResult? Function(PairChannelCommandDto_TransferFailed value)?
        transferFailed,
    TResult? Function(PairChannelCommandDto_Log value)? log,
  }) {
    return dropPair?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(PairChannelCommandDto_SendPairOffer value)? sendPairOffer,
    TResult Function(PairChannelCommandDto_SendPairJoin value)? sendPairJoin,
    TResult Function(PairChannelCommandDto_ConnectPair value)? connectPair,
    TResult Function(PairChannelCommandDto_SendFrame value)? sendFrame,
    TResult Function(PairChannelCommandDto_ClosePair value)? closePair,
    TResult Function(PairChannelCommandDto_DropPair value)? dropPair,
    TResult Function(PairChannelCommandDto_PublishRingEvent value)?
        publishRingEvent,
    TResult Function(PairChannelCommandDto_LoadHistory value)? loadHistory,
    TResult Function(PairChannelCommandDto_StoreMessages value)? storeMessages,
    TResult Function(PairChannelCommandDto_SaveMlsState value)? saveMlsState,
    TResult Function(PairChannelCommandDto_SaveRingState value)? saveRingState,
    TResult Function(PairChannelCommandDto_RingJoined value)? ringJoined,
    TResult Function(PairChannelCommandDto_DeviceAdmitted value)?
        deviceAdmitted,
    TResult Function(PairChannelCommandDto_SiblingStealthLearned value)?
        siblingStealthLearned,
    TResult Function(PairChannelCommandDto_TransferComplete value)?
        transferComplete,
    TResult Function(PairChannelCommandDto_TransferFailed value)?
        transferFailed,
    TResult Function(PairChannelCommandDto_Log value)? log,
    required TResult orElse(),
  }) {
    if (dropPair != null) {
      return dropPair(this);
    }
    return orElse();
  }
}

abstract class PairChannelCommandDto_DropPair extends PairChannelCommandDto {
  const factory PairChannelCommandDto_DropPair() =
      _$PairChannelCommandDto_DropPairImpl;
  const PairChannelCommandDto_DropPair._() : super._();
}

/// @nodoc
abstract class _$$PairChannelCommandDto_PublishRingEventImplCopyWith<$Res> {
  factory _$$PairChannelCommandDto_PublishRingEventImplCopyWith(
          _$PairChannelCommandDto_PublishRingEventImpl value,
          $Res Function(_$PairChannelCommandDto_PublishRingEventImpl) then) =
      __$$PairChannelCommandDto_PublishRingEventImplCopyWithImpl<$Res>;
  @useResult
  $Res call({Uint8List tag, Uint8List ciphertext});
}

/// @nodoc
class __$$PairChannelCommandDto_PublishRingEventImplCopyWithImpl<$Res>
    extends _$PairChannelCommandDtoCopyWithImpl<$Res,
        _$PairChannelCommandDto_PublishRingEventImpl>
    implements _$$PairChannelCommandDto_PublishRingEventImplCopyWith<$Res> {
  __$$PairChannelCommandDto_PublishRingEventImplCopyWithImpl(
      _$PairChannelCommandDto_PublishRingEventImpl _value,
      $Res Function(_$PairChannelCommandDto_PublishRingEventImpl) _then)
      : super(_value, _then);

  /// Create a copy of PairChannelCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? tag = null,
    Object? ciphertext = null,
  }) {
    return _then(_$PairChannelCommandDto_PublishRingEventImpl(
      tag: null == tag
          ? _value.tag
          : tag // ignore: cast_nullable_to_non_nullable
              as Uint8List,
      ciphertext: null == ciphertext
          ? _value.ciphertext
          : ciphertext // ignore: cast_nullable_to_non_nullable
              as Uint8List,
    ));
  }
}

/// @nodoc

class _$PairChannelCommandDto_PublishRingEventImpl
    extends PairChannelCommandDto_PublishRingEvent {
  const _$PairChannelCommandDto_PublishRingEventImpl(
      {required this.tag, required this.ciphertext})
      : super._();

  @override
  final Uint8List tag;
  @override
  final Uint8List ciphertext;

  @override
  String toString() {
    return 'PairChannelCommandDto.publishRingEvent(tag: $tag, ciphertext: $ciphertext)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$PairChannelCommandDto_PublishRingEventImpl &&
            const DeepCollectionEquality().equals(other.tag, tag) &&
            const DeepCollectionEquality()
                .equals(other.ciphertext, ciphertext));
  }

  @override
  int get hashCode => Object.hash(
      runtimeType,
      const DeepCollectionEquality().hash(tag),
      const DeepCollectionEquality().hash(ciphertext));

  /// Create a copy of PairChannelCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$PairChannelCommandDto_PublishRingEventImplCopyWith<
          _$PairChannelCommandDto_PublishRingEventImpl>
      get copyWith =>
          __$$PairChannelCommandDto_PublishRingEventImplCopyWithImpl<
              _$PairChannelCommandDto_PublishRingEventImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(String drawbridgeUrl, Uint8List token)
        sendPairOffer,
    required TResult Function(String drawbridgeUrl, Uint8List token)
        sendPairJoin,
    required TResult Function(String url, Uint8List token) connectPair,
    required TResult Function(Uint8List data) sendFrame,
    required TResult Function() closePair,
    required TResult Function() dropPair,
    required TResult Function(Uint8List tag, Uint8List ciphertext)
        publishRingEvent,
    required TResult Function(Uint8List token) loadHistory,
    required TResult Function(String convId, List<SyncMessageDto> messages)
        storeMessages,
    required TResult Function() saveMlsState,
    required TResult Function() saveRingState,
    required TResult Function(Uint8List ringId) ringJoined,
    required TResult Function(Uint8List ringId) deviceAdmitted,
    required TResult Function(Uint8List deviceId, Uint8List scanPubkey)
        siblingStealthLearned,
    required TResult Function(SyncTallyDto tally) transferComplete,
    required TResult Function(String detail, bool duringPairing) transferFailed,
    required TResult Function(String line) log,
  }) {
    return publishRingEvent(tag, ciphertext);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(String drawbridgeUrl, Uint8List token)? sendPairOffer,
    TResult? Function(String drawbridgeUrl, Uint8List token)? sendPairJoin,
    TResult? Function(String url, Uint8List token)? connectPair,
    TResult? Function(Uint8List data)? sendFrame,
    TResult? Function()? closePair,
    TResult? Function()? dropPair,
    TResult? Function(Uint8List tag, Uint8List ciphertext)? publishRingEvent,
    TResult? Function(Uint8List token)? loadHistory,
    TResult? Function(String convId, List<SyncMessageDto> messages)?
        storeMessages,
    TResult? Function()? saveMlsState,
    TResult? Function()? saveRingState,
    TResult? Function(Uint8List ringId)? ringJoined,
    TResult? Function(Uint8List ringId)? deviceAdmitted,
    TResult? Function(Uint8List deviceId, Uint8List scanPubkey)?
        siblingStealthLearned,
    TResult? Function(SyncTallyDto tally)? transferComplete,
    TResult? Function(String detail, bool duringPairing)? transferFailed,
    TResult? Function(String line)? log,
  }) {
    return publishRingEvent?.call(tag, ciphertext);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(String drawbridgeUrl, Uint8List token)? sendPairOffer,
    TResult Function(String drawbridgeUrl, Uint8List token)? sendPairJoin,
    TResult Function(String url, Uint8List token)? connectPair,
    TResult Function(Uint8List data)? sendFrame,
    TResult Function()? closePair,
    TResult Function()? dropPair,
    TResult Function(Uint8List tag, Uint8List ciphertext)? publishRingEvent,
    TResult Function(Uint8List token)? loadHistory,
    TResult Function(String convId, List<SyncMessageDto> messages)?
        storeMessages,
    TResult Function()? saveMlsState,
    TResult Function()? saveRingState,
    TResult Function(Uint8List ringId)? ringJoined,
    TResult Function(Uint8List ringId)? deviceAdmitted,
    TResult Function(Uint8List deviceId, Uint8List scanPubkey)?
        siblingStealthLearned,
    TResult Function(SyncTallyDto tally)? transferComplete,
    TResult Function(String detail, bool duringPairing)? transferFailed,
    TResult Function(String line)? log,
    required TResult orElse(),
  }) {
    if (publishRingEvent != null) {
      return publishRingEvent(tag, ciphertext);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(PairChannelCommandDto_SendPairOffer value)
        sendPairOffer,
    required TResult Function(PairChannelCommandDto_SendPairJoin value)
        sendPairJoin,
    required TResult Function(PairChannelCommandDto_ConnectPair value)
        connectPair,
    required TResult Function(PairChannelCommandDto_SendFrame value) sendFrame,
    required TResult Function(PairChannelCommandDto_ClosePair value) closePair,
    required TResult Function(PairChannelCommandDto_DropPair value) dropPair,
    required TResult Function(PairChannelCommandDto_PublishRingEvent value)
        publishRingEvent,
    required TResult Function(PairChannelCommandDto_LoadHistory value)
        loadHistory,
    required TResult Function(PairChannelCommandDto_StoreMessages value)
        storeMessages,
    required TResult Function(PairChannelCommandDto_SaveMlsState value)
        saveMlsState,
    required TResult Function(PairChannelCommandDto_SaveRingState value)
        saveRingState,
    required TResult Function(PairChannelCommandDto_RingJoined value)
        ringJoined,
    required TResult Function(PairChannelCommandDto_DeviceAdmitted value)
        deviceAdmitted,
    required TResult Function(PairChannelCommandDto_SiblingStealthLearned value)
        siblingStealthLearned,
    required TResult Function(PairChannelCommandDto_TransferComplete value)
        transferComplete,
    required TResult Function(PairChannelCommandDto_TransferFailed value)
        transferFailed,
    required TResult Function(PairChannelCommandDto_Log value) log,
  }) {
    return publishRingEvent(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(PairChannelCommandDto_SendPairOffer value)? sendPairOffer,
    TResult? Function(PairChannelCommandDto_SendPairJoin value)? sendPairJoin,
    TResult? Function(PairChannelCommandDto_ConnectPair value)? connectPair,
    TResult? Function(PairChannelCommandDto_SendFrame value)? sendFrame,
    TResult? Function(PairChannelCommandDto_ClosePair value)? closePair,
    TResult? Function(PairChannelCommandDto_DropPair value)? dropPair,
    TResult? Function(PairChannelCommandDto_PublishRingEvent value)?
        publishRingEvent,
    TResult? Function(PairChannelCommandDto_LoadHistory value)? loadHistory,
    TResult? Function(PairChannelCommandDto_StoreMessages value)? storeMessages,
    TResult? Function(PairChannelCommandDto_SaveMlsState value)? saveMlsState,
    TResult? Function(PairChannelCommandDto_SaveRingState value)? saveRingState,
    TResult? Function(PairChannelCommandDto_RingJoined value)? ringJoined,
    TResult? Function(PairChannelCommandDto_DeviceAdmitted value)?
        deviceAdmitted,
    TResult? Function(PairChannelCommandDto_SiblingStealthLearned value)?
        siblingStealthLearned,
    TResult? Function(PairChannelCommandDto_TransferComplete value)?
        transferComplete,
    TResult? Function(PairChannelCommandDto_TransferFailed value)?
        transferFailed,
    TResult? Function(PairChannelCommandDto_Log value)? log,
  }) {
    return publishRingEvent?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(PairChannelCommandDto_SendPairOffer value)? sendPairOffer,
    TResult Function(PairChannelCommandDto_SendPairJoin value)? sendPairJoin,
    TResult Function(PairChannelCommandDto_ConnectPair value)? connectPair,
    TResult Function(PairChannelCommandDto_SendFrame value)? sendFrame,
    TResult Function(PairChannelCommandDto_ClosePair value)? closePair,
    TResult Function(PairChannelCommandDto_DropPair value)? dropPair,
    TResult Function(PairChannelCommandDto_PublishRingEvent value)?
        publishRingEvent,
    TResult Function(PairChannelCommandDto_LoadHistory value)? loadHistory,
    TResult Function(PairChannelCommandDto_StoreMessages value)? storeMessages,
    TResult Function(PairChannelCommandDto_SaveMlsState value)? saveMlsState,
    TResult Function(PairChannelCommandDto_SaveRingState value)? saveRingState,
    TResult Function(PairChannelCommandDto_RingJoined value)? ringJoined,
    TResult Function(PairChannelCommandDto_DeviceAdmitted value)?
        deviceAdmitted,
    TResult Function(PairChannelCommandDto_SiblingStealthLearned value)?
        siblingStealthLearned,
    TResult Function(PairChannelCommandDto_TransferComplete value)?
        transferComplete,
    TResult Function(PairChannelCommandDto_TransferFailed value)?
        transferFailed,
    TResult Function(PairChannelCommandDto_Log value)? log,
    required TResult orElse(),
  }) {
    if (publishRingEvent != null) {
      return publishRingEvent(this);
    }
    return orElse();
  }
}

abstract class PairChannelCommandDto_PublishRingEvent
    extends PairChannelCommandDto {
  const factory PairChannelCommandDto_PublishRingEvent(
          {required final Uint8List tag, required final Uint8List ciphertext}) =
      _$PairChannelCommandDto_PublishRingEventImpl;
  const PairChannelCommandDto_PublishRingEvent._() : super._();

  Uint8List get tag;
  Uint8List get ciphertext;

  /// Create a copy of PairChannelCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$PairChannelCommandDto_PublishRingEventImplCopyWith<
          _$PairChannelCommandDto_PublishRingEventImpl>
      get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$PairChannelCommandDto_LoadHistoryImplCopyWith<$Res> {
  factory _$$PairChannelCommandDto_LoadHistoryImplCopyWith(
          _$PairChannelCommandDto_LoadHistoryImpl value,
          $Res Function(_$PairChannelCommandDto_LoadHistoryImpl) then) =
      __$$PairChannelCommandDto_LoadHistoryImplCopyWithImpl<$Res>;
  @useResult
  $Res call({Uint8List token});
}

/// @nodoc
class __$$PairChannelCommandDto_LoadHistoryImplCopyWithImpl<$Res>
    extends _$PairChannelCommandDtoCopyWithImpl<$Res,
        _$PairChannelCommandDto_LoadHistoryImpl>
    implements _$$PairChannelCommandDto_LoadHistoryImplCopyWith<$Res> {
  __$$PairChannelCommandDto_LoadHistoryImplCopyWithImpl(
      _$PairChannelCommandDto_LoadHistoryImpl _value,
      $Res Function(_$PairChannelCommandDto_LoadHistoryImpl) _then)
      : super(_value, _then);

  /// Create a copy of PairChannelCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? token = null,
  }) {
    return _then(_$PairChannelCommandDto_LoadHistoryImpl(
      token: null == token
          ? _value.token
          : token // ignore: cast_nullable_to_non_nullable
              as Uint8List,
    ));
  }
}

/// @nodoc

class _$PairChannelCommandDto_LoadHistoryImpl
    extends PairChannelCommandDto_LoadHistory {
  const _$PairChannelCommandDto_LoadHistoryImpl({required this.token})
      : super._();

  @override
  final Uint8List token;

  @override
  String toString() {
    return 'PairChannelCommandDto.loadHistory(token: $token)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$PairChannelCommandDto_LoadHistoryImpl &&
            const DeepCollectionEquality().equals(other.token, token));
  }

  @override
  int get hashCode =>
      Object.hash(runtimeType, const DeepCollectionEquality().hash(token));

  /// Create a copy of PairChannelCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$PairChannelCommandDto_LoadHistoryImplCopyWith<
          _$PairChannelCommandDto_LoadHistoryImpl>
      get copyWith => __$$PairChannelCommandDto_LoadHistoryImplCopyWithImpl<
          _$PairChannelCommandDto_LoadHistoryImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(String drawbridgeUrl, Uint8List token)
        sendPairOffer,
    required TResult Function(String drawbridgeUrl, Uint8List token)
        sendPairJoin,
    required TResult Function(String url, Uint8List token) connectPair,
    required TResult Function(Uint8List data) sendFrame,
    required TResult Function() closePair,
    required TResult Function() dropPair,
    required TResult Function(Uint8List tag, Uint8List ciphertext)
        publishRingEvent,
    required TResult Function(Uint8List token) loadHistory,
    required TResult Function(String convId, List<SyncMessageDto> messages)
        storeMessages,
    required TResult Function() saveMlsState,
    required TResult Function() saveRingState,
    required TResult Function(Uint8List ringId) ringJoined,
    required TResult Function(Uint8List ringId) deviceAdmitted,
    required TResult Function(Uint8List deviceId, Uint8List scanPubkey)
        siblingStealthLearned,
    required TResult Function(SyncTallyDto tally) transferComplete,
    required TResult Function(String detail, bool duringPairing) transferFailed,
    required TResult Function(String line) log,
  }) {
    return loadHistory(token);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(String drawbridgeUrl, Uint8List token)? sendPairOffer,
    TResult? Function(String drawbridgeUrl, Uint8List token)? sendPairJoin,
    TResult? Function(String url, Uint8List token)? connectPair,
    TResult? Function(Uint8List data)? sendFrame,
    TResult? Function()? closePair,
    TResult? Function()? dropPair,
    TResult? Function(Uint8List tag, Uint8List ciphertext)? publishRingEvent,
    TResult? Function(Uint8List token)? loadHistory,
    TResult? Function(String convId, List<SyncMessageDto> messages)?
        storeMessages,
    TResult? Function()? saveMlsState,
    TResult? Function()? saveRingState,
    TResult? Function(Uint8List ringId)? ringJoined,
    TResult? Function(Uint8List ringId)? deviceAdmitted,
    TResult? Function(Uint8List deviceId, Uint8List scanPubkey)?
        siblingStealthLearned,
    TResult? Function(SyncTallyDto tally)? transferComplete,
    TResult? Function(String detail, bool duringPairing)? transferFailed,
    TResult? Function(String line)? log,
  }) {
    return loadHistory?.call(token);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(String drawbridgeUrl, Uint8List token)? sendPairOffer,
    TResult Function(String drawbridgeUrl, Uint8List token)? sendPairJoin,
    TResult Function(String url, Uint8List token)? connectPair,
    TResult Function(Uint8List data)? sendFrame,
    TResult Function()? closePair,
    TResult Function()? dropPair,
    TResult Function(Uint8List tag, Uint8List ciphertext)? publishRingEvent,
    TResult Function(Uint8List token)? loadHistory,
    TResult Function(String convId, List<SyncMessageDto> messages)?
        storeMessages,
    TResult Function()? saveMlsState,
    TResult Function()? saveRingState,
    TResult Function(Uint8List ringId)? ringJoined,
    TResult Function(Uint8List ringId)? deviceAdmitted,
    TResult Function(Uint8List deviceId, Uint8List scanPubkey)?
        siblingStealthLearned,
    TResult Function(SyncTallyDto tally)? transferComplete,
    TResult Function(String detail, bool duringPairing)? transferFailed,
    TResult Function(String line)? log,
    required TResult orElse(),
  }) {
    if (loadHistory != null) {
      return loadHistory(token);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(PairChannelCommandDto_SendPairOffer value)
        sendPairOffer,
    required TResult Function(PairChannelCommandDto_SendPairJoin value)
        sendPairJoin,
    required TResult Function(PairChannelCommandDto_ConnectPair value)
        connectPair,
    required TResult Function(PairChannelCommandDto_SendFrame value) sendFrame,
    required TResult Function(PairChannelCommandDto_ClosePair value) closePair,
    required TResult Function(PairChannelCommandDto_DropPair value) dropPair,
    required TResult Function(PairChannelCommandDto_PublishRingEvent value)
        publishRingEvent,
    required TResult Function(PairChannelCommandDto_LoadHistory value)
        loadHistory,
    required TResult Function(PairChannelCommandDto_StoreMessages value)
        storeMessages,
    required TResult Function(PairChannelCommandDto_SaveMlsState value)
        saveMlsState,
    required TResult Function(PairChannelCommandDto_SaveRingState value)
        saveRingState,
    required TResult Function(PairChannelCommandDto_RingJoined value)
        ringJoined,
    required TResult Function(PairChannelCommandDto_DeviceAdmitted value)
        deviceAdmitted,
    required TResult Function(PairChannelCommandDto_SiblingStealthLearned value)
        siblingStealthLearned,
    required TResult Function(PairChannelCommandDto_TransferComplete value)
        transferComplete,
    required TResult Function(PairChannelCommandDto_TransferFailed value)
        transferFailed,
    required TResult Function(PairChannelCommandDto_Log value) log,
  }) {
    return loadHistory(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(PairChannelCommandDto_SendPairOffer value)? sendPairOffer,
    TResult? Function(PairChannelCommandDto_SendPairJoin value)? sendPairJoin,
    TResult? Function(PairChannelCommandDto_ConnectPair value)? connectPair,
    TResult? Function(PairChannelCommandDto_SendFrame value)? sendFrame,
    TResult? Function(PairChannelCommandDto_ClosePair value)? closePair,
    TResult? Function(PairChannelCommandDto_DropPair value)? dropPair,
    TResult? Function(PairChannelCommandDto_PublishRingEvent value)?
        publishRingEvent,
    TResult? Function(PairChannelCommandDto_LoadHistory value)? loadHistory,
    TResult? Function(PairChannelCommandDto_StoreMessages value)? storeMessages,
    TResult? Function(PairChannelCommandDto_SaveMlsState value)? saveMlsState,
    TResult? Function(PairChannelCommandDto_SaveRingState value)? saveRingState,
    TResult? Function(PairChannelCommandDto_RingJoined value)? ringJoined,
    TResult? Function(PairChannelCommandDto_DeviceAdmitted value)?
        deviceAdmitted,
    TResult? Function(PairChannelCommandDto_SiblingStealthLearned value)?
        siblingStealthLearned,
    TResult? Function(PairChannelCommandDto_TransferComplete value)?
        transferComplete,
    TResult? Function(PairChannelCommandDto_TransferFailed value)?
        transferFailed,
    TResult? Function(PairChannelCommandDto_Log value)? log,
  }) {
    return loadHistory?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(PairChannelCommandDto_SendPairOffer value)? sendPairOffer,
    TResult Function(PairChannelCommandDto_SendPairJoin value)? sendPairJoin,
    TResult Function(PairChannelCommandDto_ConnectPair value)? connectPair,
    TResult Function(PairChannelCommandDto_SendFrame value)? sendFrame,
    TResult Function(PairChannelCommandDto_ClosePair value)? closePair,
    TResult Function(PairChannelCommandDto_DropPair value)? dropPair,
    TResult Function(PairChannelCommandDto_PublishRingEvent value)?
        publishRingEvent,
    TResult Function(PairChannelCommandDto_LoadHistory value)? loadHistory,
    TResult Function(PairChannelCommandDto_StoreMessages value)? storeMessages,
    TResult Function(PairChannelCommandDto_SaveMlsState value)? saveMlsState,
    TResult Function(PairChannelCommandDto_SaveRingState value)? saveRingState,
    TResult Function(PairChannelCommandDto_RingJoined value)? ringJoined,
    TResult Function(PairChannelCommandDto_DeviceAdmitted value)?
        deviceAdmitted,
    TResult Function(PairChannelCommandDto_SiblingStealthLearned value)?
        siblingStealthLearned,
    TResult Function(PairChannelCommandDto_TransferComplete value)?
        transferComplete,
    TResult Function(PairChannelCommandDto_TransferFailed value)?
        transferFailed,
    TResult Function(PairChannelCommandDto_Log value)? log,
    required TResult orElse(),
  }) {
    if (loadHistory != null) {
      return loadHistory(this);
    }
    return orElse();
  }
}

abstract class PairChannelCommandDto_LoadHistory extends PairChannelCommandDto {
  const factory PairChannelCommandDto_LoadHistory(
          {required final Uint8List token}) =
      _$PairChannelCommandDto_LoadHistoryImpl;
  const PairChannelCommandDto_LoadHistory._() : super._();

  Uint8List get token;

  /// Create a copy of PairChannelCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$PairChannelCommandDto_LoadHistoryImplCopyWith<
          _$PairChannelCommandDto_LoadHistoryImpl>
      get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$PairChannelCommandDto_StoreMessagesImplCopyWith<$Res> {
  factory _$$PairChannelCommandDto_StoreMessagesImplCopyWith(
          _$PairChannelCommandDto_StoreMessagesImpl value,
          $Res Function(_$PairChannelCommandDto_StoreMessagesImpl) then) =
      __$$PairChannelCommandDto_StoreMessagesImplCopyWithImpl<$Res>;
  @useResult
  $Res call({String convId, List<SyncMessageDto> messages});
}

/// @nodoc
class __$$PairChannelCommandDto_StoreMessagesImplCopyWithImpl<$Res>
    extends _$PairChannelCommandDtoCopyWithImpl<$Res,
        _$PairChannelCommandDto_StoreMessagesImpl>
    implements _$$PairChannelCommandDto_StoreMessagesImplCopyWith<$Res> {
  __$$PairChannelCommandDto_StoreMessagesImplCopyWithImpl(
      _$PairChannelCommandDto_StoreMessagesImpl _value,
      $Res Function(_$PairChannelCommandDto_StoreMessagesImpl) _then)
      : super(_value, _then);

  /// Create a copy of PairChannelCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? convId = null,
    Object? messages = null,
  }) {
    return _then(_$PairChannelCommandDto_StoreMessagesImpl(
      convId: null == convId
          ? _value.convId
          : convId // ignore: cast_nullable_to_non_nullable
              as String,
      messages: null == messages
          ? _value._messages
          : messages // ignore: cast_nullable_to_non_nullable
              as List<SyncMessageDto>,
    ));
  }
}

/// @nodoc

class _$PairChannelCommandDto_StoreMessagesImpl
    extends PairChannelCommandDto_StoreMessages {
  const _$PairChannelCommandDto_StoreMessagesImpl(
      {required this.convId, required final List<SyncMessageDto> messages})
      : _messages = messages,
        super._();

  @override
  final String convId;
  final List<SyncMessageDto> _messages;
  @override
  List<SyncMessageDto> get messages {
    if (_messages is EqualUnmodifiableListView) return _messages;
    // ignore: implicit_dynamic_type
    return EqualUnmodifiableListView(_messages);
  }

  @override
  String toString() {
    return 'PairChannelCommandDto.storeMessages(convId: $convId, messages: $messages)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$PairChannelCommandDto_StoreMessagesImpl &&
            (identical(other.convId, convId) || other.convId == convId) &&
            const DeepCollectionEquality().equals(other._messages, _messages));
  }

  @override
  int get hashCode => Object.hash(
      runtimeType, convId, const DeepCollectionEquality().hash(_messages));

  /// Create a copy of PairChannelCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$PairChannelCommandDto_StoreMessagesImplCopyWith<
          _$PairChannelCommandDto_StoreMessagesImpl>
      get copyWith => __$$PairChannelCommandDto_StoreMessagesImplCopyWithImpl<
          _$PairChannelCommandDto_StoreMessagesImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(String drawbridgeUrl, Uint8List token)
        sendPairOffer,
    required TResult Function(String drawbridgeUrl, Uint8List token)
        sendPairJoin,
    required TResult Function(String url, Uint8List token) connectPair,
    required TResult Function(Uint8List data) sendFrame,
    required TResult Function() closePair,
    required TResult Function() dropPair,
    required TResult Function(Uint8List tag, Uint8List ciphertext)
        publishRingEvent,
    required TResult Function(Uint8List token) loadHistory,
    required TResult Function(String convId, List<SyncMessageDto> messages)
        storeMessages,
    required TResult Function() saveMlsState,
    required TResult Function() saveRingState,
    required TResult Function(Uint8List ringId) ringJoined,
    required TResult Function(Uint8List ringId) deviceAdmitted,
    required TResult Function(Uint8List deviceId, Uint8List scanPubkey)
        siblingStealthLearned,
    required TResult Function(SyncTallyDto tally) transferComplete,
    required TResult Function(String detail, bool duringPairing) transferFailed,
    required TResult Function(String line) log,
  }) {
    return storeMessages(convId, messages);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(String drawbridgeUrl, Uint8List token)? sendPairOffer,
    TResult? Function(String drawbridgeUrl, Uint8List token)? sendPairJoin,
    TResult? Function(String url, Uint8List token)? connectPair,
    TResult? Function(Uint8List data)? sendFrame,
    TResult? Function()? closePair,
    TResult? Function()? dropPair,
    TResult? Function(Uint8List tag, Uint8List ciphertext)? publishRingEvent,
    TResult? Function(Uint8List token)? loadHistory,
    TResult? Function(String convId, List<SyncMessageDto> messages)?
        storeMessages,
    TResult? Function()? saveMlsState,
    TResult? Function()? saveRingState,
    TResult? Function(Uint8List ringId)? ringJoined,
    TResult? Function(Uint8List ringId)? deviceAdmitted,
    TResult? Function(Uint8List deviceId, Uint8List scanPubkey)?
        siblingStealthLearned,
    TResult? Function(SyncTallyDto tally)? transferComplete,
    TResult? Function(String detail, bool duringPairing)? transferFailed,
    TResult? Function(String line)? log,
  }) {
    return storeMessages?.call(convId, messages);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(String drawbridgeUrl, Uint8List token)? sendPairOffer,
    TResult Function(String drawbridgeUrl, Uint8List token)? sendPairJoin,
    TResult Function(String url, Uint8List token)? connectPair,
    TResult Function(Uint8List data)? sendFrame,
    TResult Function()? closePair,
    TResult Function()? dropPair,
    TResult Function(Uint8List tag, Uint8List ciphertext)? publishRingEvent,
    TResult Function(Uint8List token)? loadHistory,
    TResult Function(String convId, List<SyncMessageDto> messages)?
        storeMessages,
    TResult Function()? saveMlsState,
    TResult Function()? saveRingState,
    TResult Function(Uint8List ringId)? ringJoined,
    TResult Function(Uint8List ringId)? deviceAdmitted,
    TResult Function(Uint8List deviceId, Uint8List scanPubkey)?
        siblingStealthLearned,
    TResult Function(SyncTallyDto tally)? transferComplete,
    TResult Function(String detail, bool duringPairing)? transferFailed,
    TResult Function(String line)? log,
    required TResult orElse(),
  }) {
    if (storeMessages != null) {
      return storeMessages(convId, messages);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(PairChannelCommandDto_SendPairOffer value)
        sendPairOffer,
    required TResult Function(PairChannelCommandDto_SendPairJoin value)
        sendPairJoin,
    required TResult Function(PairChannelCommandDto_ConnectPair value)
        connectPair,
    required TResult Function(PairChannelCommandDto_SendFrame value) sendFrame,
    required TResult Function(PairChannelCommandDto_ClosePair value) closePair,
    required TResult Function(PairChannelCommandDto_DropPair value) dropPair,
    required TResult Function(PairChannelCommandDto_PublishRingEvent value)
        publishRingEvent,
    required TResult Function(PairChannelCommandDto_LoadHistory value)
        loadHistory,
    required TResult Function(PairChannelCommandDto_StoreMessages value)
        storeMessages,
    required TResult Function(PairChannelCommandDto_SaveMlsState value)
        saveMlsState,
    required TResult Function(PairChannelCommandDto_SaveRingState value)
        saveRingState,
    required TResult Function(PairChannelCommandDto_RingJoined value)
        ringJoined,
    required TResult Function(PairChannelCommandDto_DeviceAdmitted value)
        deviceAdmitted,
    required TResult Function(PairChannelCommandDto_SiblingStealthLearned value)
        siblingStealthLearned,
    required TResult Function(PairChannelCommandDto_TransferComplete value)
        transferComplete,
    required TResult Function(PairChannelCommandDto_TransferFailed value)
        transferFailed,
    required TResult Function(PairChannelCommandDto_Log value) log,
  }) {
    return storeMessages(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(PairChannelCommandDto_SendPairOffer value)? sendPairOffer,
    TResult? Function(PairChannelCommandDto_SendPairJoin value)? sendPairJoin,
    TResult? Function(PairChannelCommandDto_ConnectPair value)? connectPair,
    TResult? Function(PairChannelCommandDto_SendFrame value)? sendFrame,
    TResult? Function(PairChannelCommandDto_ClosePair value)? closePair,
    TResult? Function(PairChannelCommandDto_DropPair value)? dropPair,
    TResult? Function(PairChannelCommandDto_PublishRingEvent value)?
        publishRingEvent,
    TResult? Function(PairChannelCommandDto_LoadHistory value)? loadHistory,
    TResult? Function(PairChannelCommandDto_StoreMessages value)? storeMessages,
    TResult? Function(PairChannelCommandDto_SaveMlsState value)? saveMlsState,
    TResult? Function(PairChannelCommandDto_SaveRingState value)? saveRingState,
    TResult? Function(PairChannelCommandDto_RingJoined value)? ringJoined,
    TResult? Function(PairChannelCommandDto_DeviceAdmitted value)?
        deviceAdmitted,
    TResult? Function(PairChannelCommandDto_SiblingStealthLearned value)?
        siblingStealthLearned,
    TResult? Function(PairChannelCommandDto_TransferComplete value)?
        transferComplete,
    TResult? Function(PairChannelCommandDto_TransferFailed value)?
        transferFailed,
    TResult? Function(PairChannelCommandDto_Log value)? log,
  }) {
    return storeMessages?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(PairChannelCommandDto_SendPairOffer value)? sendPairOffer,
    TResult Function(PairChannelCommandDto_SendPairJoin value)? sendPairJoin,
    TResult Function(PairChannelCommandDto_ConnectPair value)? connectPair,
    TResult Function(PairChannelCommandDto_SendFrame value)? sendFrame,
    TResult Function(PairChannelCommandDto_ClosePair value)? closePair,
    TResult Function(PairChannelCommandDto_DropPair value)? dropPair,
    TResult Function(PairChannelCommandDto_PublishRingEvent value)?
        publishRingEvent,
    TResult Function(PairChannelCommandDto_LoadHistory value)? loadHistory,
    TResult Function(PairChannelCommandDto_StoreMessages value)? storeMessages,
    TResult Function(PairChannelCommandDto_SaveMlsState value)? saveMlsState,
    TResult Function(PairChannelCommandDto_SaveRingState value)? saveRingState,
    TResult Function(PairChannelCommandDto_RingJoined value)? ringJoined,
    TResult Function(PairChannelCommandDto_DeviceAdmitted value)?
        deviceAdmitted,
    TResult Function(PairChannelCommandDto_SiblingStealthLearned value)?
        siblingStealthLearned,
    TResult Function(PairChannelCommandDto_TransferComplete value)?
        transferComplete,
    TResult Function(PairChannelCommandDto_TransferFailed value)?
        transferFailed,
    TResult Function(PairChannelCommandDto_Log value)? log,
    required TResult orElse(),
  }) {
    if (storeMessages != null) {
      return storeMessages(this);
    }
    return orElse();
  }
}

abstract class PairChannelCommandDto_StoreMessages
    extends PairChannelCommandDto {
  const factory PairChannelCommandDto_StoreMessages(
          {required final String convId,
          required final List<SyncMessageDto> messages}) =
      _$PairChannelCommandDto_StoreMessagesImpl;
  const PairChannelCommandDto_StoreMessages._() : super._();

  String get convId;
  List<SyncMessageDto> get messages;

  /// Create a copy of PairChannelCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$PairChannelCommandDto_StoreMessagesImplCopyWith<
          _$PairChannelCommandDto_StoreMessagesImpl>
      get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$PairChannelCommandDto_SaveMlsStateImplCopyWith<$Res> {
  factory _$$PairChannelCommandDto_SaveMlsStateImplCopyWith(
          _$PairChannelCommandDto_SaveMlsStateImpl value,
          $Res Function(_$PairChannelCommandDto_SaveMlsStateImpl) then) =
      __$$PairChannelCommandDto_SaveMlsStateImplCopyWithImpl<$Res>;
}

/// @nodoc
class __$$PairChannelCommandDto_SaveMlsStateImplCopyWithImpl<$Res>
    extends _$PairChannelCommandDtoCopyWithImpl<$Res,
        _$PairChannelCommandDto_SaveMlsStateImpl>
    implements _$$PairChannelCommandDto_SaveMlsStateImplCopyWith<$Res> {
  __$$PairChannelCommandDto_SaveMlsStateImplCopyWithImpl(
      _$PairChannelCommandDto_SaveMlsStateImpl _value,
      $Res Function(_$PairChannelCommandDto_SaveMlsStateImpl) _then)
      : super(_value, _then);

  /// Create a copy of PairChannelCommandDto
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc

class _$PairChannelCommandDto_SaveMlsStateImpl
    extends PairChannelCommandDto_SaveMlsState {
  const _$PairChannelCommandDto_SaveMlsStateImpl() : super._();

  @override
  String toString() {
    return 'PairChannelCommandDto.saveMlsState()';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$PairChannelCommandDto_SaveMlsStateImpl);
  }

  @override
  int get hashCode => runtimeType.hashCode;

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(String drawbridgeUrl, Uint8List token)
        sendPairOffer,
    required TResult Function(String drawbridgeUrl, Uint8List token)
        sendPairJoin,
    required TResult Function(String url, Uint8List token) connectPair,
    required TResult Function(Uint8List data) sendFrame,
    required TResult Function() closePair,
    required TResult Function() dropPair,
    required TResult Function(Uint8List tag, Uint8List ciphertext)
        publishRingEvent,
    required TResult Function(Uint8List token) loadHistory,
    required TResult Function(String convId, List<SyncMessageDto> messages)
        storeMessages,
    required TResult Function() saveMlsState,
    required TResult Function() saveRingState,
    required TResult Function(Uint8List ringId) ringJoined,
    required TResult Function(Uint8List ringId) deviceAdmitted,
    required TResult Function(Uint8List deviceId, Uint8List scanPubkey)
        siblingStealthLearned,
    required TResult Function(SyncTallyDto tally) transferComplete,
    required TResult Function(String detail, bool duringPairing) transferFailed,
    required TResult Function(String line) log,
  }) {
    return saveMlsState();
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(String drawbridgeUrl, Uint8List token)? sendPairOffer,
    TResult? Function(String drawbridgeUrl, Uint8List token)? sendPairJoin,
    TResult? Function(String url, Uint8List token)? connectPair,
    TResult? Function(Uint8List data)? sendFrame,
    TResult? Function()? closePair,
    TResult? Function()? dropPair,
    TResult? Function(Uint8List tag, Uint8List ciphertext)? publishRingEvent,
    TResult? Function(Uint8List token)? loadHistory,
    TResult? Function(String convId, List<SyncMessageDto> messages)?
        storeMessages,
    TResult? Function()? saveMlsState,
    TResult? Function()? saveRingState,
    TResult? Function(Uint8List ringId)? ringJoined,
    TResult? Function(Uint8List ringId)? deviceAdmitted,
    TResult? Function(Uint8List deviceId, Uint8List scanPubkey)?
        siblingStealthLearned,
    TResult? Function(SyncTallyDto tally)? transferComplete,
    TResult? Function(String detail, bool duringPairing)? transferFailed,
    TResult? Function(String line)? log,
  }) {
    return saveMlsState?.call();
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(String drawbridgeUrl, Uint8List token)? sendPairOffer,
    TResult Function(String drawbridgeUrl, Uint8List token)? sendPairJoin,
    TResult Function(String url, Uint8List token)? connectPair,
    TResult Function(Uint8List data)? sendFrame,
    TResult Function()? closePair,
    TResult Function()? dropPair,
    TResult Function(Uint8List tag, Uint8List ciphertext)? publishRingEvent,
    TResult Function(Uint8List token)? loadHistory,
    TResult Function(String convId, List<SyncMessageDto> messages)?
        storeMessages,
    TResult Function()? saveMlsState,
    TResult Function()? saveRingState,
    TResult Function(Uint8List ringId)? ringJoined,
    TResult Function(Uint8List ringId)? deviceAdmitted,
    TResult Function(Uint8List deviceId, Uint8List scanPubkey)?
        siblingStealthLearned,
    TResult Function(SyncTallyDto tally)? transferComplete,
    TResult Function(String detail, bool duringPairing)? transferFailed,
    TResult Function(String line)? log,
    required TResult orElse(),
  }) {
    if (saveMlsState != null) {
      return saveMlsState();
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(PairChannelCommandDto_SendPairOffer value)
        sendPairOffer,
    required TResult Function(PairChannelCommandDto_SendPairJoin value)
        sendPairJoin,
    required TResult Function(PairChannelCommandDto_ConnectPair value)
        connectPair,
    required TResult Function(PairChannelCommandDto_SendFrame value) sendFrame,
    required TResult Function(PairChannelCommandDto_ClosePair value) closePair,
    required TResult Function(PairChannelCommandDto_DropPair value) dropPair,
    required TResult Function(PairChannelCommandDto_PublishRingEvent value)
        publishRingEvent,
    required TResult Function(PairChannelCommandDto_LoadHistory value)
        loadHistory,
    required TResult Function(PairChannelCommandDto_StoreMessages value)
        storeMessages,
    required TResult Function(PairChannelCommandDto_SaveMlsState value)
        saveMlsState,
    required TResult Function(PairChannelCommandDto_SaveRingState value)
        saveRingState,
    required TResult Function(PairChannelCommandDto_RingJoined value)
        ringJoined,
    required TResult Function(PairChannelCommandDto_DeviceAdmitted value)
        deviceAdmitted,
    required TResult Function(PairChannelCommandDto_SiblingStealthLearned value)
        siblingStealthLearned,
    required TResult Function(PairChannelCommandDto_TransferComplete value)
        transferComplete,
    required TResult Function(PairChannelCommandDto_TransferFailed value)
        transferFailed,
    required TResult Function(PairChannelCommandDto_Log value) log,
  }) {
    return saveMlsState(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(PairChannelCommandDto_SendPairOffer value)? sendPairOffer,
    TResult? Function(PairChannelCommandDto_SendPairJoin value)? sendPairJoin,
    TResult? Function(PairChannelCommandDto_ConnectPair value)? connectPair,
    TResult? Function(PairChannelCommandDto_SendFrame value)? sendFrame,
    TResult? Function(PairChannelCommandDto_ClosePair value)? closePair,
    TResult? Function(PairChannelCommandDto_DropPair value)? dropPair,
    TResult? Function(PairChannelCommandDto_PublishRingEvent value)?
        publishRingEvent,
    TResult? Function(PairChannelCommandDto_LoadHistory value)? loadHistory,
    TResult? Function(PairChannelCommandDto_StoreMessages value)? storeMessages,
    TResult? Function(PairChannelCommandDto_SaveMlsState value)? saveMlsState,
    TResult? Function(PairChannelCommandDto_SaveRingState value)? saveRingState,
    TResult? Function(PairChannelCommandDto_RingJoined value)? ringJoined,
    TResult? Function(PairChannelCommandDto_DeviceAdmitted value)?
        deviceAdmitted,
    TResult? Function(PairChannelCommandDto_SiblingStealthLearned value)?
        siblingStealthLearned,
    TResult? Function(PairChannelCommandDto_TransferComplete value)?
        transferComplete,
    TResult? Function(PairChannelCommandDto_TransferFailed value)?
        transferFailed,
    TResult? Function(PairChannelCommandDto_Log value)? log,
  }) {
    return saveMlsState?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(PairChannelCommandDto_SendPairOffer value)? sendPairOffer,
    TResult Function(PairChannelCommandDto_SendPairJoin value)? sendPairJoin,
    TResult Function(PairChannelCommandDto_ConnectPair value)? connectPair,
    TResult Function(PairChannelCommandDto_SendFrame value)? sendFrame,
    TResult Function(PairChannelCommandDto_ClosePair value)? closePair,
    TResult Function(PairChannelCommandDto_DropPair value)? dropPair,
    TResult Function(PairChannelCommandDto_PublishRingEvent value)?
        publishRingEvent,
    TResult Function(PairChannelCommandDto_LoadHistory value)? loadHistory,
    TResult Function(PairChannelCommandDto_StoreMessages value)? storeMessages,
    TResult Function(PairChannelCommandDto_SaveMlsState value)? saveMlsState,
    TResult Function(PairChannelCommandDto_SaveRingState value)? saveRingState,
    TResult Function(PairChannelCommandDto_RingJoined value)? ringJoined,
    TResult Function(PairChannelCommandDto_DeviceAdmitted value)?
        deviceAdmitted,
    TResult Function(PairChannelCommandDto_SiblingStealthLearned value)?
        siblingStealthLearned,
    TResult Function(PairChannelCommandDto_TransferComplete value)?
        transferComplete,
    TResult Function(PairChannelCommandDto_TransferFailed value)?
        transferFailed,
    TResult Function(PairChannelCommandDto_Log value)? log,
    required TResult orElse(),
  }) {
    if (saveMlsState != null) {
      return saveMlsState(this);
    }
    return orElse();
  }
}

abstract class PairChannelCommandDto_SaveMlsState
    extends PairChannelCommandDto {
  const factory PairChannelCommandDto_SaveMlsState() =
      _$PairChannelCommandDto_SaveMlsStateImpl;
  const PairChannelCommandDto_SaveMlsState._() : super._();
}

/// @nodoc
abstract class _$$PairChannelCommandDto_SaveRingStateImplCopyWith<$Res> {
  factory _$$PairChannelCommandDto_SaveRingStateImplCopyWith(
          _$PairChannelCommandDto_SaveRingStateImpl value,
          $Res Function(_$PairChannelCommandDto_SaveRingStateImpl) then) =
      __$$PairChannelCommandDto_SaveRingStateImplCopyWithImpl<$Res>;
}

/// @nodoc
class __$$PairChannelCommandDto_SaveRingStateImplCopyWithImpl<$Res>
    extends _$PairChannelCommandDtoCopyWithImpl<$Res,
        _$PairChannelCommandDto_SaveRingStateImpl>
    implements _$$PairChannelCommandDto_SaveRingStateImplCopyWith<$Res> {
  __$$PairChannelCommandDto_SaveRingStateImplCopyWithImpl(
      _$PairChannelCommandDto_SaveRingStateImpl _value,
      $Res Function(_$PairChannelCommandDto_SaveRingStateImpl) _then)
      : super(_value, _then);

  /// Create a copy of PairChannelCommandDto
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc

class _$PairChannelCommandDto_SaveRingStateImpl
    extends PairChannelCommandDto_SaveRingState {
  const _$PairChannelCommandDto_SaveRingStateImpl() : super._();

  @override
  String toString() {
    return 'PairChannelCommandDto.saveRingState()';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$PairChannelCommandDto_SaveRingStateImpl);
  }

  @override
  int get hashCode => runtimeType.hashCode;

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(String drawbridgeUrl, Uint8List token)
        sendPairOffer,
    required TResult Function(String drawbridgeUrl, Uint8List token)
        sendPairJoin,
    required TResult Function(String url, Uint8List token) connectPair,
    required TResult Function(Uint8List data) sendFrame,
    required TResult Function() closePair,
    required TResult Function() dropPair,
    required TResult Function(Uint8List tag, Uint8List ciphertext)
        publishRingEvent,
    required TResult Function(Uint8List token) loadHistory,
    required TResult Function(String convId, List<SyncMessageDto> messages)
        storeMessages,
    required TResult Function() saveMlsState,
    required TResult Function() saveRingState,
    required TResult Function(Uint8List ringId) ringJoined,
    required TResult Function(Uint8List ringId) deviceAdmitted,
    required TResult Function(Uint8List deviceId, Uint8List scanPubkey)
        siblingStealthLearned,
    required TResult Function(SyncTallyDto tally) transferComplete,
    required TResult Function(String detail, bool duringPairing) transferFailed,
    required TResult Function(String line) log,
  }) {
    return saveRingState();
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(String drawbridgeUrl, Uint8List token)? sendPairOffer,
    TResult? Function(String drawbridgeUrl, Uint8List token)? sendPairJoin,
    TResult? Function(String url, Uint8List token)? connectPair,
    TResult? Function(Uint8List data)? sendFrame,
    TResult? Function()? closePair,
    TResult? Function()? dropPair,
    TResult? Function(Uint8List tag, Uint8List ciphertext)? publishRingEvent,
    TResult? Function(Uint8List token)? loadHistory,
    TResult? Function(String convId, List<SyncMessageDto> messages)?
        storeMessages,
    TResult? Function()? saveMlsState,
    TResult? Function()? saveRingState,
    TResult? Function(Uint8List ringId)? ringJoined,
    TResult? Function(Uint8List ringId)? deviceAdmitted,
    TResult? Function(Uint8List deviceId, Uint8List scanPubkey)?
        siblingStealthLearned,
    TResult? Function(SyncTallyDto tally)? transferComplete,
    TResult? Function(String detail, bool duringPairing)? transferFailed,
    TResult? Function(String line)? log,
  }) {
    return saveRingState?.call();
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(String drawbridgeUrl, Uint8List token)? sendPairOffer,
    TResult Function(String drawbridgeUrl, Uint8List token)? sendPairJoin,
    TResult Function(String url, Uint8List token)? connectPair,
    TResult Function(Uint8List data)? sendFrame,
    TResult Function()? closePair,
    TResult Function()? dropPair,
    TResult Function(Uint8List tag, Uint8List ciphertext)? publishRingEvent,
    TResult Function(Uint8List token)? loadHistory,
    TResult Function(String convId, List<SyncMessageDto> messages)?
        storeMessages,
    TResult Function()? saveMlsState,
    TResult Function()? saveRingState,
    TResult Function(Uint8List ringId)? ringJoined,
    TResult Function(Uint8List ringId)? deviceAdmitted,
    TResult Function(Uint8List deviceId, Uint8List scanPubkey)?
        siblingStealthLearned,
    TResult Function(SyncTallyDto tally)? transferComplete,
    TResult Function(String detail, bool duringPairing)? transferFailed,
    TResult Function(String line)? log,
    required TResult orElse(),
  }) {
    if (saveRingState != null) {
      return saveRingState();
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(PairChannelCommandDto_SendPairOffer value)
        sendPairOffer,
    required TResult Function(PairChannelCommandDto_SendPairJoin value)
        sendPairJoin,
    required TResult Function(PairChannelCommandDto_ConnectPair value)
        connectPair,
    required TResult Function(PairChannelCommandDto_SendFrame value) sendFrame,
    required TResult Function(PairChannelCommandDto_ClosePair value) closePair,
    required TResult Function(PairChannelCommandDto_DropPair value) dropPair,
    required TResult Function(PairChannelCommandDto_PublishRingEvent value)
        publishRingEvent,
    required TResult Function(PairChannelCommandDto_LoadHistory value)
        loadHistory,
    required TResult Function(PairChannelCommandDto_StoreMessages value)
        storeMessages,
    required TResult Function(PairChannelCommandDto_SaveMlsState value)
        saveMlsState,
    required TResult Function(PairChannelCommandDto_SaveRingState value)
        saveRingState,
    required TResult Function(PairChannelCommandDto_RingJoined value)
        ringJoined,
    required TResult Function(PairChannelCommandDto_DeviceAdmitted value)
        deviceAdmitted,
    required TResult Function(PairChannelCommandDto_SiblingStealthLearned value)
        siblingStealthLearned,
    required TResult Function(PairChannelCommandDto_TransferComplete value)
        transferComplete,
    required TResult Function(PairChannelCommandDto_TransferFailed value)
        transferFailed,
    required TResult Function(PairChannelCommandDto_Log value) log,
  }) {
    return saveRingState(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(PairChannelCommandDto_SendPairOffer value)? sendPairOffer,
    TResult? Function(PairChannelCommandDto_SendPairJoin value)? sendPairJoin,
    TResult? Function(PairChannelCommandDto_ConnectPair value)? connectPair,
    TResult? Function(PairChannelCommandDto_SendFrame value)? sendFrame,
    TResult? Function(PairChannelCommandDto_ClosePair value)? closePair,
    TResult? Function(PairChannelCommandDto_DropPair value)? dropPair,
    TResult? Function(PairChannelCommandDto_PublishRingEvent value)?
        publishRingEvent,
    TResult? Function(PairChannelCommandDto_LoadHistory value)? loadHistory,
    TResult? Function(PairChannelCommandDto_StoreMessages value)? storeMessages,
    TResult? Function(PairChannelCommandDto_SaveMlsState value)? saveMlsState,
    TResult? Function(PairChannelCommandDto_SaveRingState value)? saveRingState,
    TResult? Function(PairChannelCommandDto_RingJoined value)? ringJoined,
    TResult? Function(PairChannelCommandDto_DeviceAdmitted value)?
        deviceAdmitted,
    TResult? Function(PairChannelCommandDto_SiblingStealthLearned value)?
        siblingStealthLearned,
    TResult? Function(PairChannelCommandDto_TransferComplete value)?
        transferComplete,
    TResult? Function(PairChannelCommandDto_TransferFailed value)?
        transferFailed,
    TResult? Function(PairChannelCommandDto_Log value)? log,
  }) {
    return saveRingState?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(PairChannelCommandDto_SendPairOffer value)? sendPairOffer,
    TResult Function(PairChannelCommandDto_SendPairJoin value)? sendPairJoin,
    TResult Function(PairChannelCommandDto_ConnectPair value)? connectPair,
    TResult Function(PairChannelCommandDto_SendFrame value)? sendFrame,
    TResult Function(PairChannelCommandDto_ClosePair value)? closePair,
    TResult Function(PairChannelCommandDto_DropPair value)? dropPair,
    TResult Function(PairChannelCommandDto_PublishRingEvent value)?
        publishRingEvent,
    TResult Function(PairChannelCommandDto_LoadHistory value)? loadHistory,
    TResult Function(PairChannelCommandDto_StoreMessages value)? storeMessages,
    TResult Function(PairChannelCommandDto_SaveMlsState value)? saveMlsState,
    TResult Function(PairChannelCommandDto_SaveRingState value)? saveRingState,
    TResult Function(PairChannelCommandDto_RingJoined value)? ringJoined,
    TResult Function(PairChannelCommandDto_DeviceAdmitted value)?
        deviceAdmitted,
    TResult Function(PairChannelCommandDto_SiblingStealthLearned value)?
        siblingStealthLearned,
    TResult Function(PairChannelCommandDto_TransferComplete value)?
        transferComplete,
    TResult Function(PairChannelCommandDto_TransferFailed value)?
        transferFailed,
    TResult Function(PairChannelCommandDto_Log value)? log,
    required TResult orElse(),
  }) {
    if (saveRingState != null) {
      return saveRingState(this);
    }
    return orElse();
  }
}

abstract class PairChannelCommandDto_SaveRingState
    extends PairChannelCommandDto {
  const factory PairChannelCommandDto_SaveRingState() =
      _$PairChannelCommandDto_SaveRingStateImpl;
  const PairChannelCommandDto_SaveRingState._() : super._();
}

/// @nodoc
abstract class _$$PairChannelCommandDto_RingJoinedImplCopyWith<$Res> {
  factory _$$PairChannelCommandDto_RingJoinedImplCopyWith(
          _$PairChannelCommandDto_RingJoinedImpl value,
          $Res Function(_$PairChannelCommandDto_RingJoinedImpl) then) =
      __$$PairChannelCommandDto_RingJoinedImplCopyWithImpl<$Res>;
  @useResult
  $Res call({Uint8List ringId});
}

/// @nodoc
class __$$PairChannelCommandDto_RingJoinedImplCopyWithImpl<$Res>
    extends _$PairChannelCommandDtoCopyWithImpl<$Res,
        _$PairChannelCommandDto_RingJoinedImpl>
    implements _$$PairChannelCommandDto_RingJoinedImplCopyWith<$Res> {
  __$$PairChannelCommandDto_RingJoinedImplCopyWithImpl(
      _$PairChannelCommandDto_RingJoinedImpl _value,
      $Res Function(_$PairChannelCommandDto_RingJoinedImpl) _then)
      : super(_value, _then);

  /// Create a copy of PairChannelCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? ringId = null,
  }) {
    return _then(_$PairChannelCommandDto_RingJoinedImpl(
      ringId: null == ringId
          ? _value.ringId
          : ringId // ignore: cast_nullable_to_non_nullable
              as Uint8List,
    ));
  }
}

/// @nodoc

class _$PairChannelCommandDto_RingJoinedImpl
    extends PairChannelCommandDto_RingJoined {
  const _$PairChannelCommandDto_RingJoinedImpl({required this.ringId})
      : super._();

  @override
  final Uint8List ringId;

  @override
  String toString() {
    return 'PairChannelCommandDto.ringJoined(ringId: $ringId)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$PairChannelCommandDto_RingJoinedImpl &&
            const DeepCollectionEquality().equals(other.ringId, ringId));
  }

  @override
  int get hashCode =>
      Object.hash(runtimeType, const DeepCollectionEquality().hash(ringId));

  /// Create a copy of PairChannelCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$PairChannelCommandDto_RingJoinedImplCopyWith<
          _$PairChannelCommandDto_RingJoinedImpl>
      get copyWith => __$$PairChannelCommandDto_RingJoinedImplCopyWithImpl<
          _$PairChannelCommandDto_RingJoinedImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(String drawbridgeUrl, Uint8List token)
        sendPairOffer,
    required TResult Function(String drawbridgeUrl, Uint8List token)
        sendPairJoin,
    required TResult Function(String url, Uint8List token) connectPair,
    required TResult Function(Uint8List data) sendFrame,
    required TResult Function() closePair,
    required TResult Function() dropPair,
    required TResult Function(Uint8List tag, Uint8List ciphertext)
        publishRingEvent,
    required TResult Function(Uint8List token) loadHistory,
    required TResult Function(String convId, List<SyncMessageDto> messages)
        storeMessages,
    required TResult Function() saveMlsState,
    required TResult Function() saveRingState,
    required TResult Function(Uint8List ringId) ringJoined,
    required TResult Function(Uint8List ringId) deviceAdmitted,
    required TResult Function(Uint8List deviceId, Uint8List scanPubkey)
        siblingStealthLearned,
    required TResult Function(SyncTallyDto tally) transferComplete,
    required TResult Function(String detail, bool duringPairing) transferFailed,
    required TResult Function(String line) log,
  }) {
    return ringJoined(ringId);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(String drawbridgeUrl, Uint8List token)? sendPairOffer,
    TResult? Function(String drawbridgeUrl, Uint8List token)? sendPairJoin,
    TResult? Function(String url, Uint8List token)? connectPair,
    TResult? Function(Uint8List data)? sendFrame,
    TResult? Function()? closePair,
    TResult? Function()? dropPair,
    TResult? Function(Uint8List tag, Uint8List ciphertext)? publishRingEvent,
    TResult? Function(Uint8List token)? loadHistory,
    TResult? Function(String convId, List<SyncMessageDto> messages)?
        storeMessages,
    TResult? Function()? saveMlsState,
    TResult? Function()? saveRingState,
    TResult? Function(Uint8List ringId)? ringJoined,
    TResult? Function(Uint8List ringId)? deviceAdmitted,
    TResult? Function(Uint8List deviceId, Uint8List scanPubkey)?
        siblingStealthLearned,
    TResult? Function(SyncTallyDto tally)? transferComplete,
    TResult? Function(String detail, bool duringPairing)? transferFailed,
    TResult? Function(String line)? log,
  }) {
    return ringJoined?.call(ringId);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(String drawbridgeUrl, Uint8List token)? sendPairOffer,
    TResult Function(String drawbridgeUrl, Uint8List token)? sendPairJoin,
    TResult Function(String url, Uint8List token)? connectPair,
    TResult Function(Uint8List data)? sendFrame,
    TResult Function()? closePair,
    TResult Function()? dropPair,
    TResult Function(Uint8List tag, Uint8List ciphertext)? publishRingEvent,
    TResult Function(Uint8List token)? loadHistory,
    TResult Function(String convId, List<SyncMessageDto> messages)?
        storeMessages,
    TResult Function()? saveMlsState,
    TResult Function()? saveRingState,
    TResult Function(Uint8List ringId)? ringJoined,
    TResult Function(Uint8List ringId)? deviceAdmitted,
    TResult Function(Uint8List deviceId, Uint8List scanPubkey)?
        siblingStealthLearned,
    TResult Function(SyncTallyDto tally)? transferComplete,
    TResult Function(String detail, bool duringPairing)? transferFailed,
    TResult Function(String line)? log,
    required TResult orElse(),
  }) {
    if (ringJoined != null) {
      return ringJoined(ringId);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(PairChannelCommandDto_SendPairOffer value)
        sendPairOffer,
    required TResult Function(PairChannelCommandDto_SendPairJoin value)
        sendPairJoin,
    required TResult Function(PairChannelCommandDto_ConnectPair value)
        connectPair,
    required TResult Function(PairChannelCommandDto_SendFrame value) sendFrame,
    required TResult Function(PairChannelCommandDto_ClosePair value) closePair,
    required TResult Function(PairChannelCommandDto_DropPair value) dropPair,
    required TResult Function(PairChannelCommandDto_PublishRingEvent value)
        publishRingEvent,
    required TResult Function(PairChannelCommandDto_LoadHistory value)
        loadHistory,
    required TResult Function(PairChannelCommandDto_StoreMessages value)
        storeMessages,
    required TResult Function(PairChannelCommandDto_SaveMlsState value)
        saveMlsState,
    required TResult Function(PairChannelCommandDto_SaveRingState value)
        saveRingState,
    required TResult Function(PairChannelCommandDto_RingJoined value)
        ringJoined,
    required TResult Function(PairChannelCommandDto_DeviceAdmitted value)
        deviceAdmitted,
    required TResult Function(PairChannelCommandDto_SiblingStealthLearned value)
        siblingStealthLearned,
    required TResult Function(PairChannelCommandDto_TransferComplete value)
        transferComplete,
    required TResult Function(PairChannelCommandDto_TransferFailed value)
        transferFailed,
    required TResult Function(PairChannelCommandDto_Log value) log,
  }) {
    return ringJoined(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(PairChannelCommandDto_SendPairOffer value)? sendPairOffer,
    TResult? Function(PairChannelCommandDto_SendPairJoin value)? sendPairJoin,
    TResult? Function(PairChannelCommandDto_ConnectPair value)? connectPair,
    TResult? Function(PairChannelCommandDto_SendFrame value)? sendFrame,
    TResult? Function(PairChannelCommandDto_ClosePair value)? closePair,
    TResult? Function(PairChannelCommandDto_DropPair value)? dropPair,
    TResult? Function(PairChannelCommandDto_PublishRingEvent value)?
        publishRingEvent,
    TResult? Function(PairChannelCommandDto_LoadHistory value)? loadHistory,
    TResult? Function(PairChannelCommandDto_StoreMessages value)? storeMessages,
    TResult? Function(PairChannelCommandDto_SaveMlsState value)? saveMlsState,
    TResult? Function(PairChannelCommandDto_SaveRingState value)? saveRingState,
    TResult? Function(PairChannelCommandDto_RingJoined value)? ringJoined,
    TResult? Function(PairChannelCommandDto_DeviceAdmitted value)?
        deviceAdmitted,
    TResult? Function(PairChannelCommandDto_SiblingStealthLearned value)?
        siblingStealthLearned,
    TResult? Function(PairChannelCommandDto_TransferComplete value)?
        transferComplete,
    TResult? Function(PairChannelCommandDto_TransferFailed value)?
        transferFailed,
    TResult? Function(PairChannelCommandDto_Log value)? log,
  }) {
    return ringJoined?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(PairChannelCommandDto_SendPairOffer value)? sendPairOffer,
    TResult Function(PairChannelCommandDto_SendPairJoin value)? sendPairJoin,
    TResult Function(PairChannelCommandDto_ConnectPair value)? connectPair,
    TResult Function(PairChannelCommandDto_SendFrame value)? sendFrame,
    TResult Function(PairChannelCommandDto_ClosePair value)? closePair,
    TResult Function(PairChannelCommandDto_DropPair value)? dropPair,
    TResult Function(PairChannelCommandDto_PublishRingEvent value)?
        publishRingEvent,
    TResult Function(PairChannelCommandDto_LoadHistory value)? loadHistory,
    TResult Function(PairChannelCommandDto_StoreMessages value)? storeMessages,
    TResult Function(PairChannelCommandDto_SaveMlsState value)? saveMlsState,
    TResult Function(PairChannelCommandDto_SaveRingState value)? saveRingState,
    TResult Function(PairChannelCommandDto_RingJoined value)? ringJoined,
    TResult Function(PairChannelCommandDto_DeviceAdmitted value)?
        deviceAdmitted,
    TResult Function(PairChannelCommandDto_SiblingStealthLearned value)?
        siblingStealthLearned,
    TResult Function(PairChannelCommandDto_TransferComplete value)?
        transferComplete,
    TResult Function(PairChannelCommandDto_TransferFailed value)?
        transferFailed,
    TResult Function(PairChannelCommandDto_Log value)? log,
    required TResult orElse(),
  }) {
    if (ringJoined != null) {
      return ringJoined(this);
    }
    return orElse();
  }
}

abstract class PairChannelCommandDto_RingJoined extends PairChannelCommandDto {
  const factory PairChannelCommandDto_RingJoined(
          {required final Uint8List ringId}) =
      _$PairChannelCommandDto_RingJoinedImpl;
  const PairChannelCommandDto_RingJoined._() : super._();

  Uint8List get ringId;

  /// Create a copy of PairChannelCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$PairChannelCommandDto_RingJoinedImplCopyWith<
          _$PairChannelCommandDto_RingJoinedImpl>
      get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$PairChannelCommandDto_DeviceAdmittedImplCopyWith<$Res> {
  factory _$$PairChannelCommandDto_DeviceAdmittedImplCopyWith(
          _$PairChannelCommandDto_DeviceAdmittedImpl value,
          $Res Function(_$PairChannelCommandDto_DeviceAdmittedImpl) then) =
      __$$PairChannelCommandDto_DeviceAdmittedImplCopyWithImpl<$Res>;
  @useResult
  $Res call({Uint8List ringId});
}

/// @nodoc
class __$$PairChannelCommandDto_DeviceAdmittedImplCopyWithImpl<$Res>
    extends _$PairChannelCommandDtoCopyWithImpl<$Res,
        _$PairChannelCommandDto_DeviceAdmittedImpl>
    implements _$$PairChannelCommandDto_DeviceAdmittedImplCopyWith<$Res> {
  __$$PairChannelCommandDto_DeviceAdmittedImplCopyWithImpl(
      _$PairChannelCommandDto_DeviceAdmittedImpl _value,
      $Res Function(_$PairChannelCommandDto_DeviceAdmittedImpl) _then)
      : super(_value, _then);

  /// Create a copy of PairChannelCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? ringId = null,
  }) {
    return _then(_$PairChannelCommandDto_DeviceAdmittedImpl(
      ringId: null == ringId
          ? _value.ringId
          : ringId // ignore: cast_nullable_to_non_nullable
              as Uint8List,
    ));
  }
}

/// @nodoc

class _$PairChannelCommandDto_DeviceAdmittedImpl
    extends PairChannelCommandDto_DeviceAdmitted {
  const _$PairChannelCommandDto_DeviceAdmittedImpl({required this.ringId})
      : super._();

  @override
  final Uint8List ringId;

  @override
  String toString() {
    return 'PairChannelCommandDto.deviceAdmitted(ringId: $ringId)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$PairChannelCommandDto_DeviceAdmittedImpl &&
            const DeepCollectionEquality().equals(other.ringId, ringId));
  }

  @override
  int get hashCode =>
      Object.hash(runtimeType, const DeepCollectionEquality().hash(ringId));

  /// Create a copy of PairChannelCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$PairChannelCommandDto_DeviceAdmittedImplCopyWith<
          _$PairChannelCommandDto_DeviceAdmittedImpl>
      get copyWith => __$$PairChannelCommandDto_DeviceAdmittedImplCopyWithImpl<
          _$PairChannelCommandDto_DeviceAdmittedImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(String drawbridgeUrl, Uint8List token)
        sendPairOffer,
    required TResult Function(String drawbridgeUrl, Uint8List token)
        sendPairJoin,
    required TResult Function(String url, Uint8List token) connectPair,
    required TResult Function(Uint8List data) sendFrame,
    required TResult Function() closePair,
    required TResult Function() dropPair,
    required TResult Function(Uint8List tag, Uint8List ciphertext)
        publishRingEvent,
    required TResult Function(Uint8List token) loadHistory,
    required TResult Function(String convId, List<SyncMessageDto> messages)
        storeMessages,
    required TResult Function() saveMlsState,
    required TResult Function() saveRingState,
    required TResult Function(Uint8List ringId) ringJoined,
    required TResult Function(Uint8List ringId) deviceAdmitted,
    required TResult Function(Uint8List deviceId, Uint8List scanPubkey)
        siblingStealthLearned,
    required TResult Function(SyncTallyDto tally) transferComplete,
    required TResult Function(String detail, bool duringPairing) transferFailed,
    required TResult Function(String line) log,
  }) {
    return deviceAdmitted(ringId);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(String drawbridgeUrl, Uint8List token)? sendPairOffer,
    TResult? Function(String drawbridgeUrl, Uint8List token)? sendPairJoin,
    TResult? Function(String url, Uint8List token)? connectPair,
    TResult? Function(Uint8List data)? sendFrame,
    TResult? Function()? closePair,
    TResult? Function()? dropPair,
    TResult? Function(Uint8List tag, Uint8List ciphertext)? publishRingEvent,
    TResult? Function(Uint8List token)? loadHistory,
    TResult? Function(String convId, List<SyncMessageDto> messages)?
        storeMessages,
    TResult? Function()? saveMlsState,
    TResult? Function()? saveRingState,
    TResult? Function(Uint8List ringId)? ringJoined,
    TResult? Function(Uint8List ringId)? deviceAdmitted,
    TResult? Function(Uint8List deviceId, Uint8List scanPubkey)?
        siblingStealthLearned,
    TResult? Function(SyncTallyDto tally)? transferComplete,
    TResult? Function(String detail, bool duringPairing)? transferFailed,
    TResult? Function(String line)? log,
  }) {
    return deviceAdmitted?.call(ringId);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(String drawbridgeUrl, Uint8List token)? sendPairOffer,
    TResult Function(String drawbridgeUrl, Uint8List token)? sendPairJoin,
    TResult Function(String url, Uint8List token)? connectPair,
    TResult Function(Uint8List data)? sendFrame,
    TResult Function()? closePair,
    TResult Function()? dropPair,
    TResult Function(Uint8List tag, Uint8List ciphertext)? publishRingEvent,
    TResult Function(Uint8List token)? loadHistory,
    TResult Function(String convId, List<SyncMessageDto> messages)?
        storeMessages,
    TResult Function()? saveMlsState,
    TResult Function()? saveRingState,
    TResult Function(Uint8List ringId)? ringJoined,
    TResult Function(Uint8List ringId)? deviceAdmitted,
    TResult Function(Uint8List deviceId, Uint8List scanPubkey)?
        siblingStealthLearned,
    TResult Function(SyncTallyDto tally)? transferComplete,
    TResult Function(String detail, bool duringPairing)? transferFailed,
    TResult Function(String line)? log,
    required TResult orElse(),
  }) {
    if (deviceAdmitted != null) {
      return deviceAdmitted(ringId);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(PairChannelCommandDto_SendPairOffer value)
        sendPairOffer,
    required TResult Function(PairChannelCommandDto_SendPairJoin value)
        sendPairJoin,
    required TResult Function(PairChannelCommandDto_ConnectPair value)
        connectPair,
    required TResult Function(PairChannelCommandDto_SendFrame value) sendFrame,
    required TResult Function(PairChannelCommandDto_ClosePair value) closePair,
    required TResult Function(PairChannelCommandDto_DropPair value) dropPair,
    required TResult Function(PairChannelCommandDto_PublishRingEvent value)
        publishRingEvent,
    required TResult Function(PairChannelCommandDto_LoadHistory value)
        loadHistory,
    required TResult Function(PairChannelCommandDto_StoreMessages value)
        storeMessages,
    required TResult Function(PairChannelCommandDto_SaveMlsState value)
        saveMlsState,
    required TResult Function(PairChannelCommandDto_SaveRingState value)
        saveRingState,
    required TResult Function(PairChannelCommandDto_RingJoined value)
        ringJoined,
    required TResult Function(PairChannelCommandDto_DeviceAdmitted value)
        deviceAdmitted,
    required TResult Function(PairChannelCommandDto_SiblingStealthLearned value)
        siblingStealthLearned,
    required TResult Function(PairChannelCommandDto_TransferComplete value)
        transferComplete,
    required TResult Function(PairChannelCommandDto_TransferFailed value)
        transferFailed,
    required TResult Function(PairChannelCommandDto_Log value) log,
  }) {
    return deviceAdmitted(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(PairChannelCommandDto_SendPairOffer value)? sendPairOffer,
    TResult? Function(PairChannelCommandDto_SendPairJoin value)? sendPairJoin,
    TResult? Function(PairChannelCommandDto_ConnectPair value)? connectPair,
    TResult? Function(PairChannelCommandDto_SendFrame value)? sendFrame,
    TResult? Function(PairChannelCommandDto_ClosePair value)? closePair,
    TResult? Function(PairChannelCommandDto_DropPair value)? dropPair,
    TResult? Function(PairChannelCommandDto_PublishRingEvent value)?
        publishRingEvent,
    TResult? Function(PairChannelCommandDto_LoadHistory value)? loadHistory,
    TResult? Function(PairChannelCommandDto_StoreMessages value)? storeMessages,
    TResult? Function(PairChannelCommandDto_SaveMlsState value)? saveMlsState,
    TResult? Function(PairChannelCommandDto_SaveRingState value)? saveRingState,
    TResult? Function(PairChannelCommandDto_RingJoined value)? ringJoined,
    TResult? Function(PairChannelCommandDto_DeviceAdmitted value)?
        deviceAdmitted,
    TResult? Function(PairChannelCommandDto_SiblingStealthLearned value)?
        siblingStealthLearned,
    TResult? Function(PairChannelCommandDto_TransferComplete value)?
        transferComplete,
    TResult? Function(PairChannelCommandDto_TransferFailed value)?
        transferFailed,
    TResult? Function(PairChannelCommandDto_Log value)? log,
  }) {
    return deviceAdmitted?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(PairChannelCommandDto_SendPairOffer value)? sendPairOffer,
    TResult Function(PairChannelCommandDto_SendPairJoin value)? sendPairJoin,
    TResult Function(PairChannelCommandDto_ConnectPair value)? connectPair,
    TResult Function(PairChannelCommandDto_SendFrame value)? sendFrame,
    TResult Function(PairChannelCommandDto_ClosePair value)? closePair,
    TResult Function(PairChannelCommandDto_DropPair value)? dropPair,
    TResult Function(PairChannelCommandDto_PublishRingEvent value)?
        publishRingEvent,
    TResult Function(PairChannelCommandDto_LoadHistory value)? loadHistory,
    TResult Function(PairChannelCommandDto_StoreMessages value)? storeMessages,
    TResult Function(PairChannelCommandDto_SaveMlsState value)? saveMlsState,
    TResult Function(PairChannelCommandDto_SaveRingState value)? saveRingState,
    TResult Function(PairChannelCommandDto_RingJoined value)? ringJoined,
    TResult Function(PairChannelCommandDto_DeviceAdmitted value)?
        deviceAdmitted,
    TResult Function(PairChannelCommandDto_SiblingStealthLearned value)?
        siblingStealthLearned,
    TResult Function(PairChannelCommandDto_TransferComplete value)?
        transferComplete,
    TResult Function(PairChannelCommandDto_TransferFailed value)?
        transferFailed,
    TResult Function(PairChannelCommandDto_Log value)? log,
    required TResult orElse(),
  }) {
    if (deviceAdmitted != null) {
      return deviceAdmitted(this);
    }
    return orElse();
  }
}

abstract class PairChannelCommandDto_DeviceAdmitted
    extends PairChannelCommandDto {
  const factory PairChannelCommandDto_DeviceAdmitted(
          {required final Uint8List ringId}) =
      _$PairChannelCommandDto_DeviceAdmittedImpl;
  const PairChannelCommandDto_DeviceAdmitted._() : super._();

  Uint8List get ringId;

  /// Create a copy of PairChannelCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$PairChannelCommandDto_DeviceAdmittedImplCopyWith<
          _$PairChannelCommandDto_DeviceAdmittedImpl>
      get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$PairChannelCommandDto_SiblingStealthLearnedImplCopyWith<
    $Res> {
  factory _$$PairChannelCommandDto_SiblingStealthLearnedImplCopyWith(
          _$PairChannelCommandDto_SiblingStealthLearnedImpl value,
          $Res Function(_$PairChannelCommandDto_SiblingStealthLearnedImpl)
              then) =
      __$$PairChannelCommandDto_SiblingStealthLearnedImplCopyWithImpl<$Res>;
  @useResult
  $Res call({Uint8List deviceId, Uint8List scanPubkey});
}

/// @nodoc
class __$$PairChannelCommandDto_SiblingStealthLearnedImplCopyWithImpl<$Res>
    extends _$PairChannelCommandDtoCopyWithImpl<$Res,
        _$PairChannelCommandDto_SiblingStealthLearnedImpl>
    implements
        _$$PairChannelCommandDto_SiblingStealthLearnedImplCopyWith<$Res> {
  __$$PairChannelCommandDto_SiblingStealthLearnedImplCopyWithImpl(
      _$PairChannelCommandDto_SiblingStealthLearnedImpl _value,
      $Res Function(_$PairChannelCommandDto_SiblingStealthLearnedImpl) _then)
      : super(_value, _then);

  /// Create a copy of PairChannelCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? deviceId = null,
    Object? scanPubkey = null,
  }) {
    return _then(_$PairChannelCommandDto_SiblingStealthLearnedImpl(
      deviceId: null == deviceId
          ? _value.deviceId
          : deviceId // ignore: cast_nullable_to_non_nullable
              as Uint8List,
      scanPubkey: null == scanPubkey
          ? _value.scanPubkey
          : scanPubkey // ignore: cast_nullable_to_non_nullable
              as Uint8List,
    ));
  }
}

/// @nodoc

class _$PairChannelCommandDto_SiblingStealthLearnedImpl
    extends PairChannelCommandDto_SiblingStealthLearned {
  const _$PairChannelCommandDto_SiblingStealthLearnedImpl(
      {required this.deviceId, required this.scanPubkey})
      : super._();

  @override
  final Uint8List deviceId;
  @override
  final Uint8List scanPubkey;

  @override
  String toString() {
    return 'PairChannelCommandDto.siblingStealthLearned(deviceId: $deviceId, scanPubkey: $scanPubkey)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$PairChannelCommandDto_SiblingStealthLearnedImpl &&
            const DeepCollectionEquality().equals(other.deviceId, deviceId) &&
            const DeepCollectionEquality()
                .equals(other.scanPubkey, scanPubkey));
  }

  @override
  int get hashCode => Object.hash(
      runtimeType,
      const DeepCollectionEquality().hash(deviceId),
      const DeepCollectionEquality().hash(scanPubkey));

  /// Create a copy of PairChannelCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$PairChannelCommandDto_SiblingStealthLearnedImplCopyWith<
          _$PairChannelCommandDto_SiblingStealthLearnedImpl>
      get copyWith =>
          __$$PairChannelCommandDto_SiblingStealthLearnedImplCopyWithImpl<
                  _$PairChannelCommandDto_SiblingStealthLearnedImpl>(
              this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(String drawbridgeUrl, Uint8List token)
        sendPairOffer,
    required TResult Function(String drawbridgeUrl, Uint8List token)
        sendPairJoin,
    required TResult Function(String url, Uint8List token) connectPair,
    required TResult Function(Uint8List data) sendFrame,
    required TResult Function() closePair,
    required TResult Function() dropPair,
    required TResult Function(Uint8List tag, Uint8List ciphertext)
        publishRingEvent,
    required TResult Function(Uint8List token) loadHistory,
    required TResult Function(String convId, List<SyncMessageDto> messages)
        storeMessages,
    required TResult Function() saveMlsState,
    required TResult Function() saveRingState,
    required TResult Function(Uint8List ringId) ringJoined,
    required TResult Function(Uint8List ringId) deviceAdmitted,
    required TResult Function(Uint8List deviceId, Uint8List scanPubkey)
        siblingStealthLearned,
    required TResult Function(SyncTallyDto tally) transferComplete,
    required TResult Function(String detail, bool duringPairing) transferFailed,
    required TResult Function(String line) log,
  }) {
    return siblingStealthLearned(deviceId, scanPubkey);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(String drawbridgeUrl, Uint8List token)? sendPairOffer,
    TResult? Function(String drawbridgeUrl, Uint8List token)? sendPairJoin,
    TResult? Function(String url, Uint8List token)? connectPair,
    TResult? Function(Uint8List data)? sendFrame,
    TResult? Function()? closePair,
    TResult? Function()? dropPair,
    TResult? Function(Uint8List tag, Uint8List ciphertext)? publishRingEvent,
    TResult? Function(Uint8List token)? loadHistory,
    TResult? Function(String convId, List<SyncMessageDto> messages)?
        storeMessages,
    TResult? Function()? saveMlsState,
    TResult? Function()? saveRingState,
    TResult? Function(Uint8List ringId)? ringJoined,
    TResult? Function(Uint8List ringId)? deviceAdmitted,
    TResult? Function(Uint8List deviceId, Uint8List scanPubkey)?
        siblingStealthLearned,
    TResult? Function(SyncTallyDto tally)? transferComplete,
    TResult? Function(String detail, bool duringPairing)? transferFailed,
    TResult? Function(String line)? log,
  }) {
    return siblingStealthLearned?.call(deviceId, scanPubkey);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(String drawbridgeUrl, Uint8List token)? sendPairOffer,
    TResult Function(String drawbridgeUrl, Uint8List token)? sendPairJoin,
    TResult Function(String url, Uint8List token)? connectPair,
    TResult Function(Uint8List data)? sendFrame,
    TResult Function()? closePair,
    TResult Function()? dropPair,
    TResult Function(Uint8List tag, Uint8List ciphertext)? publishRingEvent,
    TResult Function(Uint8List token)? loadHistory,
    TResult Function(String convId, List<SyncMessageDto> messages)?
        storeMessages,
    TResult Function()? saveMlsState,
    TResult Function()? saveRingState,
    TResult Function(Uint8List ringId)? ringJoined,
    TResult Function(Uint8List ringId)? deviceAdmitted,
    TResult Function(Uint8List deviceId, Uint8List scanPubkey)?
        siblingStealthLearned,
    TResult Function(SyncTallyDto tally)? transferComplete,
    TResult Function(String detail, bool duringPairing)? transferFailed,
    TResult Function(String line)? log,
    required TResult orElse(),
  }) {
    if (siblingStealthLearned != null) {
      return siblingStealthLearned(deviceId, scanPubkey);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(PairChannelCommandDto_SendPairOffer value)
        sendPairOffer,
    required TResult Function(PairChannelCommandDto_SendPairJoin value)
        sendPairJoin,
    required TResult Function(PairChannelCommandDto_ConnectPair value)
        connectPair,
    required TResult Function(PairChannelCommandDto_SendFrame value) sendFrame,
    required TResult Function(PairChannelCommandDto_ClosePair value) closePair,
    required TResult Function(PairChannelCommandDto_DropPair value) dropPair,
    required TResult Function(PairChannelCommandDto_PublishRingEvent value)
        publishRingEvent,
    required TResult Function(PairChannelCommandDto_LoadHistory value)
        loadHistory,
    required TResult Function(PairChannelCommandDto_StoreMessages value)
        storeMessages,
    required TResult Function(PairChannelCommandDto_SaveMlsState value)
        saveMlsState,
    required TResult Function(PairChannelCommandDto_SaveRingState value)
        saveRingState,
    required TResult Function(PairChannelCommandDto_RingJoined value)
        ringJoined,
    required TResult Function(PairChannelCommandDto_DeviceAdmitted value)
        deviceAdmitted,
    required TResult Function(PairChannelCommandDto_SiblingStealthLearned value)
        siblingStealthLearned,
    required TResult Function(PairChannelCommandDto_TransferComplete value)
        transferComplete,
    required TResult Function(PairChannelCommandDto_TransferFailed value)
        transferFailed,
    required TResult Function(PairChannelCommandDto_Log value) log,
  }) {
    return siblingStealthLearned(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(PairChannelCommandDto_SendPairOffer value)? sendPairOffer,
    TResult? Function(PairChannelCommandDto_SendPairJoin value)? sendPairJoin,
    TResult? Function(PairChannelCommandDto_ConnectPair value)? connectPair,
    TResult? Function(PairChannelCommandDto_SendFrame value)? sendFrame,
    TResult? Function(PairChannelCommandDto_ClosePair value)? closePair,
    TResult? Function(PairChannelCommandDto_DropPair value)? dropPair,
    TResult? Function(PairChannelCommandDto_PublishRingEvent value)?
        publishRingEvent,
    TResult? Function(PairChannelCommandDto_LoadHistory value)? loadHistory,
    TResult? Function(PairChannelCommandDto_StoreMessages value)? storeMessages,
    TResult? Function(PairChannelCommandDto_SaveMlsState value)? saveMlsState,
    TResult? Function(PairChannelCommandDto_SaveRingState value)? saveRingState,
    TResult? Function(PairChannelCommandDto_RingJoined value)? ringJoined,
    TResult? Function(PairChannelCommandDto_DeviceAdmitted value)?
        deviceAdmitted,
    TResult? Function(PairChannelCommandDto_SiblingStealthLearned value)?
        siblingStealthLearned,
    TResult? Function(PairChannelCommandDto_TransferComplete value)?
        transferComplete,
    TResult? Function(PairChannelCommandDto_TransferFailed value)?
        transferFailed,
    TResult? Function(PairChannelCommandDto_Log value)? log,
  }) {
    return siblingStealthLearned?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(PairChannelCommandDto_SendPairOffer value)? sendPairOffer,
    TResult Function(PairChannelCommandDto_SendPairJoin value)? sendPairJoin,
    TResult Function(PairChannelCommandDto_ConnectPair value)? connectPair,
    TResult Function(PairChannelCommandDto_SendFrame value)? sendFrame,
    TResult Function(PairChannelCommandDto_ClosePair value)? closePair,
    TResult Function(PairChannelCommandDto_DropPair value)? dropPair,
    TResult Function(PairChannelCommandDto_PublishRingEvent value)?
        publishRingEvent,
    TResult Function(PairChannelCommandDto_LoadHistory value)? loadHistory,
    TResult Function(PairChannelCommandDto_StoreMessages value)? storeMessages,
    TResult Function(PairChannelCommandDto_SaveMlsState value)? saveMlsState,
    TResult Function(PairChannelCommandDto_SaveRingState value)? saveRingState,
    TResult Function(PairChannelCommandDto_RingJoined value)? ringJoined,
    TResult Function(PairChannelCommandDto_DeviceAdmitted value)?
        deviceAdmitted,
    TResult Function(PairChannelCommandDto_SiblingStealthLearned value)?
        siblingStealthLearned,
    TResult Function(PairChannelCommandDto_TransferComplete value)?
        transferComplete,
    TResult Function(PairChannelCommandDto_TransferFailed value)?
        transferFailed,
    TResult Function(PairChannelCommandDto_Log value)? log,
    required TResult orElse(),
  }) {
    if (siblingStealthLearned != null) {
      return siblingStealthLearned(this);
    }
    return orElse();
  }
}

abstract class PairChannelCommandDto_SiblingStealthLearned
    extends PairChannelCommandDto {
  const factory PairChannelCommandDto_SiblingStealthLearned(
          {required final Uint8List deviceId,
          required final Uint8List scanPubkey}) =
      _$PairChannelCommandDto_SiblingStealthLearnedImpl;
  const PairChannelCommandDto_SiblingStealthLearned._() : super._();

  Uint8List get deviceId;
  Uint8List get scanPubkey;

  /// Create a copy of PairChannelCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$PairChannelCommandDto_SiblingStealthLearnedImplCopyWith<
          _$PairChannelCommandDto_SiblingStealthLearnedImpl>
      get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$PairChannelCommandDto_TransferCompleteImplCopyWith<$Res> {
  factory _$$PairChannelCommandDto_TransferCompleteImplCopyWith(
          _$PairChannelCommandDto_TransferCompleteImpl value,
          $Res Function(_$PairChannelCommandDto_TransferCompleteImpl) then) =
      __$$PairChannelCommandDto_TransferCompleteImplCopyWithImpl<$Res>;
  @useResult
  $Res call({SyncTallyDto tally});
}

/// @nodoc
class __$$PairChannelCommandDto_TransferCompleteImplCopyWithImpl<$Res>
    extends _$PairChannelCommandDtoCopyWithImpl<$Res,
        _$PairChannelCommandDto_TransferCompleteImpl>
    implements _$$PairChannelCommandDto_TransferCompleteImplCopyWith<$Res> {
  __$$PairChannelCommandDto_TransferCompleteImplCopyWithImpl(
      _$PairChannelCommandDto_TransferCompleteImpl _value,
      $Res Function(_$PairChannelCommandDto_TransferCompleteImpl) _then)
      : super(_value, _then);

  /// Create a copy of PairChannelCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? tally = null,
  }) {
    return _then(_$PairChannelCommandDto_TransferCompleteImpl(
      tally: null == tally
          ? _value.tally
          : tally // ignore: cast_nullable_to_non_nullable
              as SyncTallyDto,
    ));
  }
}

/// @nodoc

class _$PairChannelCommandDto_TransferCompleteImpl
    extends PairChannelCommandDto_TransferComplete {
  const _$PairChannelCommandDto_TransferCompleteImpl({required this.tally})
      : super._();

  @override
  final SyncTallyDto tally;

  @override
  String toString() {
    return 'PairChannelCommandDto.transferComplete(tally: $tally)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$PairChannelCommandDto_TransferCompleteImpl &&
            (identical(other.tally, tally) || other.tally == tally));
  }

  @override
  int get hashCode => Object.hash(runtimeType, tally);

  /// Create a copy of PairChannelCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$PairChannelCommandDto_TransferCompleteImplCopyWith<
          _$PairChannelCommandDto_TransferCompleteImpl>
      get copyWith =>
          __$$PairChannelCommandDto_TransferCompleteImplCopyWithImpl<
              _$PairChannelCommandDto_TransferCompleteImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(String drawbridgeUrl, Uint8List token)
        sendPairOffer,
    required TResult Function(String drawbridgeUrl, Uint8List token)
        sendPairJoin,
    required TResult Function(String url, Uint8List token) connectPair,
    required TResult Function(Uint8List data) sendFrame,
    required TResult Function() closePair,
    required TResult Function() dropPair,
    required TResult Function(Uint8List tag, Uint8List ciphertext)
        publishRingEvent,
    required TResult Function(Uint8List token) loadHistory,
    required TResult Function(String convId, List<SyncMessageDto> messages)
        storeMessages,
    required TResult Function() saveMlsState,
    required TResult Function() saveRingState,
    required TResult Function(Uint8List ringId) ringJoined,
    required TResult Function(Uint8List ringId) deviceAdmitted,
    required TResult Function(Uint8List deviceId, Uint8List scanPubkey)
        siblingStealthLearned,
    required TResult Function(SyncTallyDto tally) transferComplete,
    required TResult Function(String detail, bool duringPairing) transferFailed,
    required TResult Function(String line) log,
  }) {
    return transferComplete(tally);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(String drawbridgeUrl, Uint8List token)? sendPairOffer,
    TResult? Function(String drawbridgeUrl, Uint8List token)? sendPairJoin,
    TResult? Function(String url, Uint8List token)? connectPair,
    TResult? Function(Uint8List data)? sendFrame,
    TResult? Function()? closePair,
    TResult? Function()? dropPair,
    TResult? Function(Uint8List tag, Uint8List ciphertext)? publishRingEvent,
    TResult? Function(Uint8List token)? loadHistory,
    TResult? Function(String convId, List<SyncMessageDto> messages)?
        storeMessages,
    TResult? Function()? saveMlsState,
    TResult? Function()? saveRingState,
    TResult? Function(Uint8List ringId)? ringJoined,
    TResult? Function(Uint8List ringId)? deviceAdmitted,
    TResult? Function(Uint8List deviceId, Uint8List scanPubkey)?
        siblingStealthLearned,
    TResult? Function(SyncTallyDto tally)? transferComplete,
    TResult? Function(String detail, bool duringPairing)? transferFailed,
    TResult? Function(String line)? log,
  }) {
    return transferComplete?.call(tally);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(String drawbridgeUrl, Uint8List token)? sendPairOffer,
    TResult Function(String drawbridgeUrl, Uint8List token)? sendPairJoin,
    TResult Function(String url, Uint8List token)? connectPair,
    TResult Function(Uint8List data)? sendFrame,
    TResult Function()? closePair,
    TResult Function()? dropPair,
    TResult Function(Uint8List tag, Uint8List ciphertext)? publishRingEvent,
    TResult Function(Uint8List token)? loadHistory,
    TResult Function(String convId, List<SyncMessageDto> messages)?
        storeMessages,
    TResult Function()? saveMlsState,
    TResult Function()? saveRingState,
    TResult Function(Uint8List ringId)? ringJoined,
    TResult Function(Uint8List ringId)? deviceAdmitted,
    TResult Function(Uint8List deviceId, Uint8List scanPubkey)?
        siblingStealthLearned,
    TResult Function(SyncTallyDto tally)? transferComplete,
    TResult Function(String detail, bool duringPairing)? transferFailed,
    TResult Function(String line)? log,
    required TResult orElse(),
  }) {
    if (transferComplete != null) {
      return transferComplete(tally);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(PairChannelCommandDto_SendPairOffer value)
        sendPairOffer,
    required TResult Function(PairChannelCommandDto_SendPairJoin value)
        sendPairJoin,
    required TResult Function(PairChannelCommandDto_ConnectPair value)
        connectPair,
    required TResult Function(PairChannelCommandDto_SendFrame value) sendFrame,
    required TResult Function(PairChannelCommandDto_ClosePair value) closePair,
    required TResult Function(PairChannelCommandDto_DropPair value) dropPair,
    required TResult Function(PairChannelCommandDto_PublishRingEvent value)
        publishRingEvent,
    required TResult Function(PairChannelCommandDto_LoadHistory value)
        loadHistory,
    required TResult Function(PairChannelCommandDto_StoreMessages value)
        storeMessages,
    required TResult Function(PairChannelCommandDto_SaveMlsState value)
        saveMlsState,
    required TResult Function(PairChannelCommandDto_SaveRingState value)
        saveRingState,
    required TResult Function(PairChannelCommandDto_RingJoined value)
        ringJoined,
    required TResult Function(PairChannelCommandDto_DeviceAdmitted value)
        deviceAdmitted,
    required TResult Function(PairChannelCommandDto_SiblingStealthLearned value)
        siblingStealthLearned,
    required TResult Function(PairChannelCommandDto_TransferComplete value)
        transferComplete,
    required TResult Function(PairChannelCommandDto_TransferFailed value)
        transferFailed,
    required TResult Function(PairChannelCommandDto_Log value) log,
  }) {
    return transferComplete(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(PairChannelCommandDto_SendPairOffer value)? sendPairOffer,
    TResult? Function(PairChannelCommandDto_SendPairJoin value)? sendPairJoin,
    TResult? Function(PairChannelCommandDto_ConnectPair value)? connectPair,
    TResult? Function(PairChannelCommandDto_SendFrame value)? sendFrame,
    TResult? Function(PairChannelCommandDto_ClosePair value)? closePair,
    TResult? Function(PairChannelCommandDto_DropPair value)? dropPair,
    TResult? Function(PairChannelCommandDto_PublishRingEvent value)?
        publishRingEvent,
    TResult? Function(PairChannelCommandDto_LoadHistory value)? loadHistory,
    TResult? Function(PairChannelCommandDto_StoreMessages value)? storeMessages,
    TResult? Function(PairChannelCommandDto_SaveMlsState value)? saveMlsState,
    TResult? Function(PairChannelCommandDto_SaveRingState value)? saveRingState,
    TResult? Function(PairChannelCommandDto_RingJoined value)? ringJoined,
    TResult? Function(PairChannelCommandDto_DeviceAdmitted value)?
        deviceAdmitted,
    TResult? Function(PairChannelCommandDto_SiblingStealthLearned value)?
        siblingStealthLearned,
    TResult? Function(PairChannelCommandDto_TransferComplete value)?
        transferComplete,
    TResult? Function(PairChannelCommandDto_TransferFailed value)?
        transferFailed,
    TResult? Function(PairChannelCommandDto_Log value)? log,
  }) {
    return transferComplete?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(PairChannelCommandDto_SendPairOffer value)? sendPairOffer,
    TResult Function(PairChannelCommandDto_SendPairJoin value)? sendPairJoin,
    TResult Function(PairChannelCommandDto_ConnectPair value)? connectPair,
    TResult Function(PairChannelCommandDto_SendFrame value)? sendFrame,
    TResult Function(PairChannelCommandDto_ClosePair value)? closePair,
    TResult Function(PairChannelCommandDto_DropPair value)? dropPair,
    TResult Function(PairChannelCommandDto_PublishRingEvent value)?
        publishRingEvent,
    TResult Function(PairChannelCommandDto_LoadHistory value)? loadHistory,
    TResult Function(PairChannelCommandDto_StoreMessages value)? storeMessages,
    TResult Function(PairChannelCommandDto_SaveMlsState value)? saveMlsState,
    TResult Function(PairChannelCommandDto_SaveRingState value)? saveRingState,
    TResult Function(PairChannelCommandDto_RingJoined value)? ringJoined,
    TResult Function(PairChannelCommandDto_DeviceAdmitted value)?
        deviceAdmitted,
    TResult Function(PairChannelCommandDto_SiblingStealthLearned value)?
        siblingStealthLearned,
    TResult Function(PairChannelCommandDto_TransferComplete value)?
        transferComplete,
    TResult Function(PairChannelCommandDto_TransferFailed value)?
        transferFailed,
    TResult Function(PairChannelCommandDto_Log value)? log,
    required TResult orElse(),
  }) {
    if (transferComplete != null) {
      return transferComplete(this);
    }
    return orElse();
  }
}

abstract class PairChannelCommandDto_TransferComplete
    extends PairChannelCommandDto {
  const factory PairChannelCommandDto_TransferComplete(
          {required final SyncTallyDto tally}) =
      _$PairChannelCommandDto_TransferCompleteImpl;
  const PairChannelCommandDto_TransferComplete._() : super._();

  SyncTallyDto get tally;

  /// Create a copy of PairChannelCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$PairChannelCommandDto_TransferCompleteImplCopyWith<
          _$PairChannelCommandDto_TransferCompleteImpl>
      get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$PairChannelCommandDto_TransferFailedImplCopyWith<$Res> {
  factory _$$PairChannelCommandDto_TransferFailedImplCopyWith(
          _$PairChannelCommandDto_TransferFailedImpl value,
          $Res Function(_$PairChannelCommandDto_TransferFailedImpl) then) =
      __$$PairChannelCommandDto_TransferFailedImplCopyWithImpl<$Res>;
  @useResult
  $Res call({String detail, bool duringPairing});
}

/// @nodoc
class __$$PairChannelCommandDto_TransferFailedImplCopyWithImpl<$Res>
    extends _$PairChannelCommandDtoCopyWithImpl<$Res,
        _$PairChannelCommandDto_TransferFailedImpl>
    implements _$$PairChannelCommandDto_TransferFailedImplCopyWith<$Res> {
  __$$PairChannelCommandDto_TransferFailedImplCopyWithImpl(
      _$PairChannelCommandDto_TransferFailedImpl _value,
      $Res Function(_$PairChannelCommandDto_TransferFailedImpl) _then)
      : super(_value, _then);

  /// Create a copy of PairChannelCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? detail = null,
    Object? duringPairing = null,
  }) {
    return _then(_$PairChannelCommandDto_TransferFailedImpl(
      detail: null == detail
          ? _value.detail
          : detail // ignore: cast_nullable_to_non_nullable
              as String,
      duringPairing: null == duringPairing
          ? _value.duringPairing
          : duringPairing // ignore: cast_nullable_to_non_nullable
              as bool,
    ));
  }
}

/// @nodoc

class _$PairChannelCommandDto_TransferFailedImpl
    extends PairChannelCommandDto_TransferFailed {
  const _$PairChannelCommandDto_TransferFailedImpl(
      {required this.detail, required this.duringPairing})
      : super._();

  @override
  final String detail;
  @override
  final bool duringPairing;

  @override
  String toString() {
    return 'PairChannelCommandDto.transferFailed(detail: $detail, duringPairing: $duringPairing)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$PairChannelCommandDto_TransferFailedImpl &&
            (identical(other.detail, detail) || other.detail == detail) &&
            (identical(other.duringPairing, duringPairing) ||
                other.duringPairing == duringPairing));
  }

  @override
  int get hashCode => Object.hash(runtimeType, detail, duringPairing);

  /// Create a copy of PairChannelCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$PairChannelCommandDto_TransferFailedImplCopyWith<
          _$PairChannelCommandDto_TransferFailedImpl>
      get copyWith => __$$PairChannelCommandDto_TransferFailedImplCopyWithImpl<
          _$PairChannelCommandDto_TransferFailedImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(String drawbridgeUrl, Uint8List token)
        sendPairOffer,
    required TResult Function(String drawbridgeUrl, Uint8List token)
        sendPairJoin,
    required TResult Function(String url, Uint8List token) connectPair,
    required TResult Function(Uint8List data) sendFrame,
    required TResult Function() closePair,
    required TResult Function() dropPair,
    required TResult Function(Uint8List tag, Uint8List ciphertext)
        publishRingEvent,
    required TResult Function(Uint8List token) loadHistory,
    required TResult Function(String convId, List<SyncMessageDto> messages)
        storeMessages,
    required TResult Function() saveMlsState,
    required TResult Function() saveRingState,
    required TResult Function(Uint8List ringId) ringJoined,
    required TResult Function(Uint8List ringId) deviceAdmitted,
    required TResult Function(Uint8List deviceId, Uint8List scanPubkey)
        siblingStealthLearned,
    required TResult Function(SyncTallyDto tally) transferComplete,
    required TResult Function(String detail, bool duringPairing) transferFailed,
    required TResult Function(String line) log,
  }) {
    return transferFailed(detail, duringPairing);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(String drawbridgeUrl, Uint8List token)? sendPairOffer,
    TResult? Function(String drawbridgeUrl, Uint8List token)? sendPairJoin,
    TResult? Function(String url, Uint8List token)? connectPair,
    TResult? Function(Uint8List data)? sendFrame,
    TResult? Function()? closePair,
    TResult? Function()? dropPair,
    TResult? Function(Uint8List tag, Uint8List ciphertext)? publishRingEvent,
    TResult? Function(Uint8List token)? loadHistory,
    TResult? Function(String convId, List<SyncMessageDto> messages)?
        storeMessages,
    TResult? Function()? saveMlsState,
    TResult? Function()? saveRingState,
    TResult? Function(Uint8List ringId)? ringJoined,
    TResult? Function(Uint8List ringId)? deviceAdmitted,
    TResult? Function(Uint8List deviceId, Uint8List scanPubkey)?
        siblingStealthLearned,
    TResult? Function(SyncTallyDto tally)? transferComplete,
    TResult? Function(String detail, bool duringPairing)? transferFailed,
    TResult? Function(String line)? log,
  }) {
    return transferFailed?.call(detail, duringPairing);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(String drawbridgeUrl, Uint8List token)? sendPairOffer,
    TResult Function(String drawbridgeUrl, Uint8List token)? sendPairJoin,
    TResult Function(String url, Uint8List token)? connectPair,
    TResult Function(Uint8List data)? sendFrame,
    TResult Function()? closePair,
    TResult Function()? dropPair,
    TResult Function(Uint8List tag, Uint8List ciphertext)? publishRingEvent,
    TResult Function(Uint8List token)? loadHistory,
    TResult Function(String convId, List<SyncMessageDto> messages)?
        storeMessages,
    TResult Function()? saveMlsState,
    TResult Function()? saveRingState,
    TResult Function(Uint8List ringId)? ringJoined,
    TResult Function(Uint8List ringId)? deviceAdmitted,
    TResult Function(Uint8List deviceId, Uint8List scanPubkey)?
        siblingStealthLearned,
    TResult Function(SyncTallyDto tally)? transferComplete,
    TResult Function(String detail, bool duringPairing)? transferFailed,
    TResult Function(String line)? log,
    required TResult orElse(),
  }) {
    if (transferFailed != null) {
      return transferFailed(detail, duringPairing);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(PairChannelCommandDto_SendPairOffer value)
        sendPairOffer,
    required TResult Function(PairChannelCommandDto_SendPairJoin value)
        sendPairJoin,
    required TResult Function(PairChannelCommandDto_ConnectPair value)
        connectPair,
    required TResult Function(PairChannelCommandDto_SendFrame value) sendFrame,
    required TResult Function(PairChannelCommandDto_ClosePair value) closePair,
    required TResult Function(PairChannelCommandDto_DropPair value) dropPair,
    required TResult Function(PairChannelCommandDto_PublishRingEvent value)
        publishRingEvent,
    required TResult Function(PairChannelCommandDto_LoadHistory value)
        loadHistory,
    required TResult Function(PairChannelCommandDto_StoreMessages value)
        storeMessages,
    required TResult Function(PairChannelCommandDto_SaveMlsState value)
        saveMlsState,
    required TResult Function(PairChannelCommandDto_SaveRingState value)
        saveRingState,
    required TResult Function(PairChannelCommandDto_RingJoined value)
        ringJoined,
    required TResult Function(PairChannelCommandDto_DeviceAdmitted value)
        deviceAdmitted,
    required TResult Function(PairChannelCommandDto_SiblingStealthLearned value)
        siblingStealthLearned,
    required TResult Function(PairChannelCommandDto_TransferComplete value)
        transferComplete,
    required TResult Function(PairChannelCommandDto_TransferFailed value)
        transferFailed,
    required TResult Function(PairChannelCommandDto_Log value) log,
  }) {
    return transferFailed(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(PairChannelCommandDto_SendPairOffer value)? sendPairOffer,
    TResult? Function(PairChannelCommandDto_SendPairJoin value)? sendPairJoin,
    TResult? Function(PairChannelCommandDto_ConnectPair value)? connectPair,
    TResult? Function(PairChannelCommandDto_SendFrame value)? sendFrame,
    TResult? Function(PairChannelCommandDto_ClosePair value)? closePair,
    TResult? Function(PairChannelCommandDto_DropPair value)? dropPair,
    TResult? Function(PairChannelCommandDto_PublishRingEvent value)?
        publishRingEvent,
    TResult? Function(PairChannelCommandDto_LoadHistory value)? loadHistory,
    TResult? Function(PairChannelCommandDto_StoreMessages value)? storeMessages,
    TResult? Function(PairChannelCommandDto_SaveMlsState value)? saveMlsState,
    TResult? Function(PairChannelCommandDto_SaveRingState value)? saveRingState,
    TResult? Function(PairChannelCommandDto_RingJoined value)? ringJoined,
    TResult? Function(PairChannelCommandDto_DeviceAdmitted value)?
        deviceAdmitted,
    TResult? Function(PairChannelCommandDto_SiblingStealthLearned value)?
        siblingStealthLearned,
    TResult? Function(PairChannelCommandDto_TransferComplete value)?
        transferComplete,
    TResult? Function(PairChannelCommandDto_TransferFailed value)?
        transferFailed,
    TResult? Function(PairChannelCommandDto_Log value)? log,
  }) {
    return transferFailed?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(PairChannelCommandDto_SendPairOffer value)? sendPairOffer,
    TResult Function(PairChannelCommandDto_SendPairJoin value)? sendPairJoin,
    TResult Function(PairChannelCommandDto_ConnectPair value)? connectPair,
    TResult Function(PairChannelCommandDto_SendFrame value)? sendFrame,
    TResult Function(PairChannelCommandDto_ClosePair value)? closePair,
    TResult Function(PairChannelCommandDto_DropPair value)? dropPair,
    TResult Function(PairChannelCommandDto_PublishRingEvent value)?
        publishRingEvent,
    TResult Function(PairChannelCommandDto_LoadHistory value)? loadHistory,
    TResult Function(PairChannelCommandDto_StoreMessages value)? storeMessages,
    TResult Function(PairChannelCommandDto_SaveMlsState value)? saveMlsState,
    TResult Function(PairChannelCommandDto_SaveRingState value)? saveRingState,
    TResult Function(PairChannelCommandDto_RingJoined value)? ringJoined,
    TResult Function(PairChannelCommandDto_DeviceAdmitted value)?
        deviceAdmitted,
    TResult Function(PairChannelCommandDto_SiblingStealthLearned value)?
        siblingStealthLearned,
    TResult Function(PairChannelCommandDto_TransferComplete value)?
        transferComplete,
    TResult Function(PairChannelCommandDto_TransferFailed value)?
        transferFailed,
    TResult Function(PairChannelCommandDto_Log value)? log,
    required TResult orElse(),
  }) {
    if (transferFailed != null) {
      return transferFailed(this);
    }
    return orElse();
  }
}

abstract class PairChannelCommandDto_TransferFailed
    extends PairChannelCommandDto {
  const factory PairChannelCommandDto_TransferFailed(
          {required final String detail, required final bool duringPairing}) =
      _$PairChannelCommandDto_TransferFailedImpl;
  const PairChannelCommandDto_TransferFailed._() : super._();

  String get detail;
  bool get duringPairing;

  /// Create a copy of PairChannelCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$PairChannelCommandDto_TransferFailedImplCopyWith<
          _$PairChannelCommandDto_TransferFailedImpl>
      get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$PairChannelCommandDto_LogImplCopyWith<$Res> {
  factory _$$PairChannelCommandDto_LogImplCopyWith(
          _$PairChannelCommandDto_LogImpl value,
          $Res Function(_$PairChannelCommandDto_LogImpl) then) =
      __$$PairChannelCommandDto_LogImplCopyWithImpl<$Res>;
  @useResult
  $Res call({String line});
}

/// @nodoc
class __$$PairChannelCommandDto_LogImplCopyWithImpl<$Res>
    extends _$PairChannelCommandDtoCopyWithImpl<$Res,
        _$PairChannelCommandDto_LogImpl>
    implements _$$PairChannelCommandDto_LogImplCopyWith<$Res> {
  __$$PairChannelCommandDto_LogImplCopyWithImpl(
      _$PairChannelCommandDto_LogImpl _value,
      $Res Function(_$PairChannelCommandDto_LogImpl) _then)
      : super(_value, _then);

  /// Create a copy of PairChannelCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? line = null,
  }) {
    return _then(_$PairChannelCommandDto_LogImpl(
      line: null == line
          ? _value.line
          : line // ignore: cast_nullable_to_non_nullable
              as String,
    ));
  }
}

/// @nodoc

class _$PairChannelCommandDto_LogImpl extends PairChannelCommandDto_Log {
  const _$PairChannelCommandDto_LogImpl({required this.line}) : super._();

  @override
  final String line;

  @override
  String toString() {
    return 'PairChannelCommandDto.log(line: $line)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$PairChannelCommandDto_LogImpl &&
            (identical(other.line, line) || other.line == line));
  }

  @override
  int get hashCode => Object.hash(runtimeType, line);

  /// Create a copy of PairChannelCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$PairChannelCommandDto_LogImplCopyWith<_$PairChannelCommandDto_LogImpl>
      get copyWith => __$$PairChannelCommandDto_LogImplCopyWithImpl<
          _$PairChannelCommandDto_LogImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(String drawbridgeUrl, Uint8List token)
        sendPairOffer,
    required TResult Function(String drawbridgeUrl, Uint8List token)
        sendPairJoin,
    required TResult Function(String url, Uint8List token) connectPair,
    required TResult Function(Uint8List data) sendFrame,
    required TResult Function() closePair,
    required TResult Function() dropPair,
    required TResult Function(Uint8List tag, Uint8List ciphertext)
        publishRingEvent,
    required TResult Function(Uint8List token) loadHistory,
    required TResult Function(String convId, List<SyncMessageDto> messages)
        storeMessages,
    required TResult Function() saveMlsState,
    required TResult Function() saveRingState,
    required TResult Function(Uint8List ringId) ringJoined,
    required TResult Function(Uint8List ringId) deviceAdmitted,
    required TResult Function(Uint8List deviceId, Uint8List scanPubkey)
        siblingStealthLearned,
    required TResult Function(SyncTallyDto tally) transferComplete,
    required TResult Function(String detail, bool duringPairing) transferFailed,
    required TResult Function(String line) log,
  }) {
    return log(line);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(String drawbridgeUrl, Uint8List token)? sendPairOffer,
    TResult? Function(String drawbridgeUrl, Uint8List token)? sendPairJoin,
    TResult? Function(String url, Uint8List token)? connectPair,
    TResult? Function(Uint8List data)? sendFrame,
    TResult? Function()? closePair,
    TResult? Function()? dropPair,
    TResult? Function(Uint8List tag, Uint8List ciphertext)? publishRingEvent,
    TResult? Function(Uint8List token)? loadHistory,
    TResult? Function(String convId, List<SyncMessageDto> messages)?
        storeMessages,
    TResult? Function()? saveMlsState,
    TResult? Function()? saveRingState,
    TResult? Function(Uint8List ringId)? ringJoined,
    TResult? Function(Uint8List ringId)? deviceAdmitted,
    TResult? Function(Uint8List deviceId, Uint8List scanPubkey)?
        siblingStealthLearned,
    TResult? Function(SyncTallyDto tally)? transferComplete,
    TResult? Function(String detail, bool duringPairing)? transferFailed,
    TResult? Function(String line)? log,
  }) {
    return log?.call(line);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(String drawbridgeUrl, Uint8List token)? sendPairOffer,
    TResult Function(String drawbridgeUrl, Uint8List token)? sendPairJoin,
    TResult Function(String url, Uint8List token)? connectPair,
    TResult Function(Uint8List data)? sendFrame,
    TResult Function()? closePair,
    TResult Function()? dropPair,
    TResult Function(Uint8List tag, Uint8List ciphertext)? publishRingEvent,
    TResult Function(Uint8List token)? loadHistory,
    TResult Function(String convId, List<SyncMessageDto> messages)?
        storeMessages,
    TResult Function()? saveMlsState,
    TResult Function()? saveRingState,
    TResult Function(Uint8List ringId)? ringJoined,
    TResult Function(Uint8List ringId)? deviceAdmitted,
    TResult Function(Uint8List deviceId, Uint8List scanPubkey)?
        siblingStealthLearned,
    TResult Function(SyncTallyDto tally)? transferComplete,
    TResult Function(String detail, bool duringPairing)? transferFailed,
    TResult Function(String line)? log,
    required TResult orElse(),
  }) {
    if (log != null) {
      return log(line);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(PairChannelCommandDto_SendPairOffer value)
        sendPairOffer,
    required TResult Function(PairChannelCommandDto_SendPairJoin value)
        sendPairJoin,
    required TResult Function(PairChannelCommandDto_ConnectPair value)
        connectPair,
    required TResult Function(PairChannelCommandDto_SendFrame value) sendFrame,
    required TResult Function(PairChannelCommandDto_ClosePair value) closePair,
    required TResult Function(PairChannelCommandDto_DropPair value) dropPair,
    required TResult Function(PairChannelCommandDto_PublishRingEvent value)
        publishRingEvent,
    required TResult Function(PairChannelCommandDto_LoadHistory value)
        loadHistory,
    required TResult Function(PairChannelCommandDto_StoreMessages value)
        storeMessages,
    required TResult Function(PairChannelCommandDto_SaveMlsState value)
        saveMlsState,
    required TResult Function(PairChannelCommandDto_SaveRingState value)
        saveRingState,
    required TResult Function(PairChannelCommandDto_RingJoined value)
        ringJoined,
    required TResult Function(PairChannelCommandDto_DeviceAdmitted value)
        deviceAdmitted,
    required TResult Function(PairChannelCommandDto_SiblingStealthLearned value)
        siblingStealthLearned,
    required TResult Function(PairChannelCommandDto_TransferComplete value)
        transferComplete,
    required TResult Function(PairChannelCommandDto_TransferFailed value)
        transferFailed,
    required TResult Function(PairChannelCommandDto_Log value) log,
  }) {
    return log(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(PairChannelCommandDto_SendPairOffer value)? sendPairOffer,
    TResult? Function(PairChannelCommandDto_SendPairJoin value)? sendPairJoin,
    TResult? Function(PairChannelCommandDto_ConnectPair value)? connectPair,
    TResult? Function(PairChannelCommandDto_SendFrame value)? sendFrame,
    TResult? Function(PairChannelCommandDto_ClosePair value)? closePair,
    TResult? Function(PairChannelCommandDto_DropPair value)? dropPair,
    TResult? Function(PairChannelCommandDto_PublishRingEvent value)?
        publishRingEvent,
    TResult? Function(PairChannelCommandDto_LoadHistory value)? loadHistory,
    TResult? Function(PairChannelCommandDto_StoreMessages value)? storeMessages,
    TResult? Function(PairChannelCommandDto_SaveMlsState value)? saveMlsState,
    TResult? Function(PairChannelCommandDto_SaveRingState value)? saveRingState,
    TResult? Function(PairChannelCommandDto_RingJoined value)? ringJoined,
    TResult? Function(PairChannelCommandDto_DeviceAdmitted value)?
        deviceAdmitted,
    TResult? Function(PairChannelCommandDto_SiblingStealthLearned value)?
        siblingStealthLearned,
    TResult? Function(PairChannelCommandDto_TransferComplete value)?
        transferComplete,
    TResult? Function(PairChannelCommandDto_TransferFailed value)?
        transferFailed,
    TResult? Function(PairChannelCommandDto_Log value)? log,
  }) {
    return log?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(PairChannelCommandDto_SendPairOffer value)? sendPairOffer,
    TResult Function(PairChannelCommandDto_SendPairJoin value)? sendPairJoin,
    TResult Function(PairChannelCommandDto_ConnectPair value)? connectPair,
    TResult Function(PairChannelCommandDto_SendFrame value)? sendFrame,
    TResult Function(PairChannelCommandDto_ClosePair value)? closePair,
    TResult Function(PairChannelCommandDto_DropPair value)? dropPair,
    TResult Function(PairChannelCommandDto_PublishRingEvent value)?
        publishRingEvent,
    TResult Function(PairChannelCommandDto_LoadHistory value)? loadHistory,
    TResult Function(PairChannelCommandDto_StoreMessages value)? storeMessages,
    TResult Function(PairChannelCommandDto_SaveMlsState value)? saveMlsState,
    TResult Function(PairChannelCommandDto_SaveRingState value)? saveRingState,
    TResult Function(PairChannelCommandDto_RingJoined value)? ringJoined,
    TResult Function(PairChannelCommandDto_DeviceAdmitted value)?
        deviceAdmitted,
    TResult Function(PairChannelCommandDto_SiblingStealthLearned value)?
        siblingStealthLearned,
    TResult Function(PairChannelCommandDto_TransferComplete value)?
        transferComplete,
    TResult Function(PairChannelCommandDto_TransferFailed value)?
        transferFailed,
    TResult Function(PairChannelCommandDto_Log value)? log,
    required TResult orElse(),
  }) {
    if (log != null) {
      return log(this);
    }
    return orElse();
  }
}

abstract class PairChannelCommandDto_Log extends PairChannelCommandDto {
  const factory PairChannelCommandDto_Log({required final String line}) =
      _$PairChannelCommandDto_LogImpl;
  const PairChannelCommandDto_Log._() : super._();

  String get line;

  /// Create a copy of PairChannelCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$PairChannelCommandDto_LogImplCopyWith<_$PairChannelCommandDto_LogImpl>
      get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
mixin _$PairingUiStateDto {
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() idle,
    required TResult Function(String code, String drawbridgeUrl, String uri)
        showingCode,
    required TResult Function() awaitingPeer,
    required TResult Function(String deviceName, String did) awaitingApproval,
    required TResult Function(Uint8List ringId) done,
    required TResult Function(String reason) failed,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function()? idle,
    TResult? Function(String code, String drawbridgeUrl, String uri)?
        showingCode,
    TResult? Function()? awaitingPeer,
    TResult? Function(String deviceName, String did)? awaitingApproval,
    TResult? Function(Uint8List ringId)? done,
    TResult? Function(String reason)? failed,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? idle,
    TResult Function(String code, String drawbridgeUrl, String uri)?
        showingCode,
    TResult Function()? awaitingPeer,
    TResult Function(String deviceName, String did)? awaitingApproval,
    TResult Function(Uint8List ringId)? done,
    TResult Function(String reason)? failed,
    required TResult orElse(),
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(PairingUiStateDto_Idle value) idle,
    required TResult Function(PairingUiStateDto_ShowingCode value) showingCode,
    required TResult Function(PairingUiStateDto_AwaitingPeer value)
        awaitingPeer,
    required TResult Function(PairingUiStateDto_AwaitingApproval value)
        awaitingApproval,
    required TResult Function(PairingUiStateDto_Done value) done,
    required TResult Function(PairingUiStateDto_Failed value) failed,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(PairingUiStateDto_Idle value)? idle,
    TResult? Function(PairingUiStateDto_ShowingCode value)? showingCode,
    TResult? Function(PairingUiStateDto_AwaitingPeer value)? awaitingPeer,
    TResult? Function(PairingUiStateDto_AwaitingApproval value)?
        awaitingApproval,
    TResult? Function(PairingUiStateDto_Done value)? done,
    TResult? Function(PairingUiStateDto_Failed value)? failed,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(PairingUiStateDto_Idle value)? idle,
    TResult Function(PairingUiStateDto_ShowingCode value)? showingCode,
    TResult Function(PairingUiStateDto_AwaitingPeer value)? awaitingPeer,
    TResult Function(PairingUiStateDto_AwaitingApproval value)?
        awaitingApproval,
    TResult Function(PairingUiStateDto_Done value)? done,
    TResult Function(PairingUiStateDto_Failed value)? failed,
    required TResult orElse(),
  }) =>
      throw _privateConstructorUsedError;
}

/// @nodoc
abstract class $PairingUiStateDtoCopyWith<$Res> {
  factory $PairingUiStateDtoCopyWith(
          PairingUiStateDto value, $Res Function(PairingUiStateDto) then) =
      _$PairingUiStateDtoCopyWithImpl<$Res, PairingUiStateDto>;
}

/// @nodoc
class _$PairingUiStateDtoCopyWithImpl<$Res, $Val extends PairingUiStateDto>
    implements $PairingUiStateDtoCopyWith<$Res> {
  _$PairingUiStateDtoCopyWithImpl(this._value, this._then);

  // ignore: unused_field
  final $Val _value;
  // ignore: unused_field
  final $Res Function($Val) _then;

  /// Create a copy of PairingUiStateDto
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc
abstract class _$$PairingUiStateDto_IdleImplCopyWith<$Res> {
  factory _$$PairingUiStateDto_IdleImplCopyWith(
          _$PairingUiStateDto_IdleImpl value,
          $Res Function(_$PairingUiStateDto_IdleImpl) then) =
      __$$PairingUiStateDto_IdleImplCopyWithImpl<$Res>;
}

/// @nodoc
class __$$PairingUiStateDto_IdleImplCopyWithImpl<$Res>
    extends _$PairingUiStateDtoCopyWithImpl<$Res, _$PairingUiStateDto_IdleImpl>
    implements _$$PairingUiStateDto_IdleImplCopyWith<$Res> {
  __$$PairingUiStateDto_IdleImplCopyWithImpl(
      _$PairingUiStateDto_IdleImpl _value,
      $Res Function(_$PairingUiStateDto_IdleImpl) _then)
      : super(_value, _then);

  /// Create a copy of PairingUiStateDto
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc

class _$PairingUiStateDto_IdleImpl extends PairingUiStateDto_Idle {
  const _$PairingUiStateDto_IdleImpl() : super._();

  @override
  String toString() {
    return 'PairingUiStateDto.idle()';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$PairingUiStateDto_IdleImpl);
  }

  @override
  int get hashCode => runtimeType.hashCode;

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() idle,
    required TResult Function(String code, String drawbridgeUrl, String uri)
        showingCode,
    required TResult Function() awaitingPeer,
    required TResult Function(String deviceName, String did) awaitingApproval,
    required TResult Function(Uint8List ringId) done,
    required TResult Function(String reason) failed,
  }) {
    return idle();
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function()? idle,
    TResult? Function(String code, String drawbridgeUrl, String uri)?
        showingCode,
    TResult? Function()? awaitingPeer,
    TResult? Function(String deviceName, String did)? awaitingApproval,
    TResult? Function(Uint8List ringId)? done,
    TResult? Function(String reason)? failed,
  }) {
    return idle?.call();
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? idle,
    TResult Function(String code, String drawbridgeUrl, String uri)?
        showingCode,
    TResult Function()? awaitingPeer,
    TResult Function(String deviceName, String did)? awaitingApproval,
    TResult Function(Uint8List ringId)? done,
    TResult Function(String reason)? failed,
    required TResult orElse(),
  }) {
    if (idle != null) {
      return idle();
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(PairingUiStateDto_Idle value) idle,
    required TResult Function(PairingUiStateDto_ShowingCode value) showingCode,
    required TResult Function(PairingUiStateDto_AwaitingPeer value)
        awaitingPeer,
    required TResult Function(PairingUiStateDto_AwaitingApproval value)
        awaitingApproval,
    required TResult Function(PairingUiStateDto_Done value) done,
    required TResult Function(PairingUiStateDto_Failed value) failed,
  }) {
    return idle(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(PairingUiStateDto_Idle value)? idle,
    TResult? Function(PairingUiStateDto_ShowingCode value)? showingCode,
    TResult? Function(PairingUiStateDto_AwaitingPeer value)? awaitingPeer,
    TResult? Function(PairingUiStateDto_AwaitingApproval value)?
        awaitingApproval,
    TResult? Function(PairingUiStateDto_Done value)? done,
    TResult? Function(PairingUiStateDto_Failed value)? failed,
  }) {
    return idle?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(PairingUiStateDto_Idle value)? idle,
    TResult Function(PairingUiStateDto_ShowingCode value)? showingCode,
    TResult Function(PairingUiStateDto_AwaitingPeer value)? awaitingPeer,
    TResult Function(PairingUiStateDto_AwaitingApproval value)?
        awaitingApproval,
    TResult Function(PairingUiStateDto_Done value)? done,
    TResult Function(PairingUiStateDto_Failed value)? failed,
    required TResult orElse(),
  }) {
    if (idle != null) {
      return idle(this);
    }
    return orElse();
  }
}

abstract class PairingUiStateDto_Idle extends PairingUiStateDto {
  const factory PairingUiStateDto_Idle() = _$PairingUiStateDto_IdleImpl;
  const PairingUiStateDto_Idle._() : super._();
}

/// @nodoc
abstract class _$$PairingUiStateDto_ShowingCodeImplCopyWith<$Res> {
  factory _$$PairingUiStateDto_ShowingCodeImplCopyWith(
          _$PairingUiStateDto_ShowingCodeImpl value,
          $Res Function(_$PairingUiStateDto_ShowingCodeImpl) then) =
      __$$PairingUiStateDto_ShowingCodeImplCopyWithImpl<$Res>;
  @useResult
  $Res call({String code, String drawbridgeUrl, String uri});
}

/// @nodoc
class __$$PairingUiStateDto_ShowingCodeImplCopyWithImpl<$Res>
    extends _$PairingUiStateDtoCopyWithImpl<$Res,
        _$PairingUiStateDto_ShowingCodeImpl>
    implements _$$PairingUiStateDto_ShowingCodeImplCopyWith<$Res> {
  __$$PairingUiStateDto_ShowingCodeImplCopyWithImpl(
      _$PairingUiStateDto_ShowingCodeImpl _value,
      $Res Function(_$PairingUiStateDto_ShowingCodeImpl) _then)
      : super(_value, _then);

  /// Create a copy of PairingUiStateDto
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? code = null,
    Object? drawbridgeUrl = null,
    Object? uri = null,
  }) {
    return _then(_$PairingUiStateDto_ShowingCodeImpl(
      code: null == code
          ? _value.code
          : code // ignore: cast_nullable_to_non_nullable
              as String,
      drawbridgeUrl: null == drawbridgeUrl
          ? _value.drawbridgeUrl
          : drawbridgeUrl // ignore: cast_nullable_to_non_nullable
              as String,
      uri: null == uri
          ? _value.uri
          : uri // ignore: cast_nullable_to_non_nullable
              as String,
    ));
  }
}

/// @nodoc

class _$PairingUiStateDto_ShowingCodeImpl
    extends PairingUiStateDto_ShowingCode {
  const _$PairingUiStateDto_ShowingCodeImpl(
      {required this.code, required this.drawbridgeUrl, required this.uri})
      : super._();

  @override
  final String code;
  @override
  final String drawbridgeUrl;
  @override
  final String uri;

  @override
  String toString() {
    return 'PairingUiStateDto.showingCode(code: $code, drawbridgeUrl: $drawbridgeUrl, uri: $uri)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$PairingUiStateDto_ShowingCodeImpl &&
            (identical(other.code, code) || other.code == code) &&
            (identical(other.drawbridgeUrl, drawbridgeUrl) ||
                other.drawbridgeUrl == drawbridgeUrl) &&
            (identical(other.uri, uri) || other.uri == uri));
  }

  @override
  int get hashCode => Object.hash(runtimeType, code, drawbridgeUrl, uri);

  /// Create a copy of PairingUiStateDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$PairingUiStateDto_ShowingCodeImplCopyWith<
          _$PairingUiStateDto_ShowingCodeImpl>
      get copyWith => __$$PairingUiStateDto_ShowingCodeImplCopyWithImpl<
          _$PairingUiStateDto_ShowingCodeImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() idle,
    required TResult Function(String code, String drawbridgeUrl, String uri)
        showingCode,
    required TResult Function() awaitingPeer,
    required TResult Function(String deviceName, String did) awaitingApproval,
    required TResult Function(Uint8List ringId) done,
    required TResult Function(String reason) failed,
  }) {
    return showingCode(code, drawbridgeUrl, uri);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function()? idle,
    TResult? Function(String code, String drawbridgeUrl, String uri)?
        showingCode,
    TResult? Function()? awaitingPeer,
    TResult? Function(String deviceName, String did)? awaitingApproval,
    TResult? Function(Uint8List ringId)? done,
    TResult? Function(String reason)? failed,
  }) {
    return showingCode?.call(code, drawbridgeUrl, uri);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? idle,
    TResult Function(String code, String drawbridgeUrl, String uri)?
        showingCode,
    TResult Function()? awaitingPeer,
    TResult Function(String deviceName, String did)? awaitingApproval,
    TResult Function(Uint8List ringId)? done,
    TResult Function(String reason)? failed,
    required TResult orElse(),
  }) {
    if (showingCode != null) {
      return showingCode(code, drawbridgeUrl, uri);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(PairingUiStateDto_Idle value) idle,
    required TResult Function(PairingUiStateDto_ShowingCode value) showingCode,
    required TResult Function(PairingUiStateDto_AwaitingPeer value)
        awaitingPeer,
    required TResult Function(PairingUiStateDto_AwaitingApproval value)
        awaitingApproval,
    required TResult Function(PairingUiStateDto_Done value) done,
    required TResult Function(PairingUiStateDto_Failed value) failed,
  }) {
    return showingCode(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(PairingUiStateDto_Idle value)? idle,
    TResult? Function(PairingUiStateDto_ShowingCode value)? showingCode,
    TResult? Function(PairingUiStateDto_AwaitingPeer value)? awaitingPeer,
    TResult? Function(PairingUiStateDto_AwaitingApproval value)?
        awaitingApproval,
    TResult? Function(PairingUiStateDto_Done value)? done,
    TResult? Function(PairingUiStateDto_Failed value)? failed,
  }) {
    return showingCode?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(PairingUiStateDto_Idle value)? idle,
    TResult Function(PairingUiStateDto_ShowingCode value)? showingCode,
    TResult Function(PairingUiStateDto_AwaitingPeer value)? awaitingPeer,
    TResult Function(PairingUiStateDto_AwaitingApproval value)?
        awaitingApproval,
    TResult Function(PairingUiStateDto_Done value)? done,
    TResult Function(PairingUiStateDto_Failed value)? failed,
    required TResult orElse(),
  }) {
    if (showingCode != null) {
      return showingCode(this);
    }
    return orElse();
  }
}

abstract class PairingUiStateDto_ShowingCode extends PairingUiStateDto {
  const factory PairingUiStateDto_ShowingCode(
      {required final String code,
      required final String drawbridgeUrl,
      required final String uri}) = _$PairingUiStateDto_ShowingCodeImpl;
  const PairingUiStateDto_ShowingCode._() : super._();

  String get code;
  String get drawbridgeUrl;
  String get uri;

  /// Create a copy of PairingUiStateDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$PairingUiStateDto_ShowingCodeImplCopyWith<
          _$PairingUiStateDto_ShowingCodeImpl>
      get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$PairingUiStateDto_AwaitingPeerImplCopyWith<$Res> {
  factory _$$PairingUiStateDto_AwaitingPeerImplCopyWith(
          _$PairingUiStateDto_AwaitingPeerImpl value,
          $Res Function(_$PairingUiStateDto_AwaitingPeerImpl) then) =
      __$$PairingUiStateDto_AwaitingPeerImplCopyWithImpl<$Res>;
}

/// @nodoc
class __$$PairingUiStateDto_AwaitingPeerImplCopyWithImpl<$Res>
    extends _$PairingUiStateDtoCopyWithImpl<$Res,
        _$PairingUiStateDto_AwaitingPeerImpl>
    implements _$$PairingUiStateDto_AwaitingPeerImplCopyWith<$Res> {
  __$$PairingUiStateDto_AwaitingPeerImplCopyWithImpl(
      _$PairingUiStateDto_AwaitingPeerImpl _value,
      $Res Function(_$PairingUiStateDto_AwaitingPeerImpl) _then)
      : super(_value, _then);

  /// Create a copy of PairingUiStateDto
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc

class _$PairingUiStateDto_AwaitingPeerImpl
    extends PairingUiStateDto_AwaitingPeer {
  const _$PairingUiStateDto_AwaitingPeerImpl() : super._();

  @override
  String toString() {
    return 'PairingUiStateDto.awaitingPeer()';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$PairingUiStateDto_AwaitingPeerImpl);
  }

  @override
  int get hashCode => runtimeType.hashCode;

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() idle,
    required TResult Function(String code, String drawbridgeUrl, String uri)
        showingCode,
    required TResult Function() awaitingPeer,
    required TResult Function(String deviceName, String did) awaitingApproval,
    required TResult Function(Uint8List ringId) done,
    required TResult Function(String reason) failed,
  }) {
    return awaitingPeer();
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function()? idle,
    TResult? Function(String code, String drawbridgeUrl, String uri)?
        showingCode,
    TResult? Function()? awaitingPeer,
    TResult? Function(String deviceName, String did)? awaitingApproval,
    TResult? Function(Uint8List ringId)? done,
    TResult? Function(String reason)? failed,
  }) {
    return awaitingPeer?.call();
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? idle,
    TResult Function(String code, String drawbridgeUrl, String uri)?
        showingCode,
    TResult Function()? awaitingPeer,
    TResult Function(String deviceName, String did)? awaitingApproval,
    TResult Function(Uint8List ringId)? done,
    TResult Function(String reason)? failed,
    required TResult orElse(),
  }) {
    if (awaitingPeer != null) {
      return awaitingPeer();
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(PairingUiStateDto_Idle value) idle,
    required TResult Function(PairingUiStateDto_ShowingCode value) showingCode,
    required TResult Function(PairingUiStateDto_AwaitingPeer value)
        awaitingPeer,
    required TResult Function(PairingUiStateDto_AwaitingApproval value)
        awaitingApproval,
    required TResult Function(PairingUiStateDto_Done value) done,
    required TResult Function(PairingUiStateDto_Failed value) failed,
  }) {
    return awaitingPeer(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(PairingUiStateDto_Idle value)? idle,
    TResult? Function(PairingUiStateDto_ShowingCode value)? showingCode,
    TResult? Function(PairingUiStateDto_AwaitingPeer value)? awaitingPeer,
    TResult? Function(PairingUiStateDto_AwaitingApproval value)?
        awaitingApproval,
    TResult? Function(PairingUiStateDto_Done value)? done,
    TResult? Function(PairingUiStateDto_Failed value)? failed,
  }) {
    return awaitingPeer?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(PairingUiStateDto_Idle value)? idle,
    TResult Function(PairingUiStateDto_ShowingCode value)? showingCode,
    TResult Function(PairingUiStateDto_AwaitingPeer value)? awaitingPeer,
    TResult Function(PairingUiStateDto_AwaitingApproval value)?
        awaitingApproval,
    TResult Function(PairingUiStateDto_Done value)? done,
    TResult Function(PairingUiStateDto_Failed value)? failed,
    required TResult orElse(),
  }) {
    if (awaitingPeer != null) {
      return awaitingPeer(this);
    }
    return orElse();
  }
}

abstract class PairingUiStateDto_AwaitingPeer extends PairingUiStateDto {
  const factory PairingUiStateDto_AwaitingPeer() =
      _$PairingUiStateDto_AwaitingPeerImpl;
  const PairingUiStateDto_AwaitingPeer._() : super._();
}

/// @nodoc
abstract class _$$PairingUiStateDto_AwaitingApprovalImplCopyWith<$Res> {
  factory _$$PairingUiStateDto_AwaitingApprovalImplCopyWith(
          _$PairingUiStateDto_AwaitingApprovalImpl value,
          $Res Function(_$PairingUiStateDto_AwaitingApprovalImpl) then) =
      __$$PairingUiStateDto_AwaitingApprovalImplCopyWithImpl<$Res>;
  @useResult
  $Res call({String deviceName, String did});
}

/// @nodoc
class __$$PairingUiStateDto_AwaitingApprovalImplCopyWithImpl<$Res>
    extends _$PairingUiStateDtoCopyWithImpl<$Res,
        _$PairingUiStateDto_AwaitingApprovalImpl>
    implements _$$PairingUiStateDto_AwaitingApprovalImplCopyWith<$Res> {
  __$$PairingUiStateDto_AwaitingApprovalImplCopyWithImpl(
      _$PairingUiStateDto_AwaitingApprovalImpl _value,
      $Res Function(_$PairingUiStateDto_AwaitingApprovalImpl) _then)
      : super(_value, _then);

  /// Create a copy of PairingUiStateDto
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? deviceName = null,
    Object? did = null,
  }) {
    return _then(_$PairingUiStateDto_AwaitingApprovalImpl(
      deviceName: null == deviceName
          ? _value.deviceName
          : deviceName // ignore: cast_nullable_to_non_nullable
              as String,
      did: null == did
          ? _value.did
          : did // ignore: cast_nullable_to_non_nullable
              as String,
    ));
  }
}

/// @nodoc

class _$PairingUiStateDto_AwaitingApprovalImpl
    extends PairingUiStateDto_AwaitingApproval {
  const _$PairingUiStateDto_AwaitingApprovalImpl(
      {required this.deviceName, required this.did})
      : super._();

  @override
  final String deviceName;
  @override
  final String did;

  @override
  String toString() {
    return 'PairingUiStateDto.awaitingApproval(deviceName: $deviceName, did: $did)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$PairingUiStateDto_AwaitingApprovalImpl &&
            (identical(other.deviceName, deviceName) ||
                other.deviceName == deviceName) &&
            (identical(other.did, did) || other.did == did));
  }

  @override
  int get hashCode => Object.hash(runtimeType, deviceName, did);

  /// Create a copy of PairingUiStateDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$PairingUiStateDto_AwaitingApprovalImplCopyWith<
          _$PairingUiStateDto_AwaitingApprovalImpl>
      get copyWith => __$$PairingUiStateDto_AwaitingApprovalImplCopyWithImpl<
          _$PairingUiStateDto_AwaitingApprovalImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() idle,
    required TResult Function(String code, String drawbridgeUrl, String uri)
        showingCode,
    required TResult Function() awaitingPeer,
    required TResult Function(String deviceName, String did) awaitingApproval,
    required TResult Function(Uint8List ringId) done,
    required TResult Function(String reason) failed,
  }) {
    return awaitingApproval(deviceName, did);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function()? idle,
    TResult? Function(String code, String drawbridgeUrl, String uri)?
        showingCode,
    TResult? Function()? awaitingPeer,
    TResult? Function(String deviceName, String did)? awaitingApproval,
    TResult? Function(Uint8List ringId)? done,
    TResult? Function(String reason)? failed,
  }) {
    return awaitingApproval?.call(deviceName, did);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? idle,
    TResult Function(String code, String drawbridgeUrl, String uri)?
        showingCode,
    TResult Function()? awaitingPeer,
    TResult Function(String deviceName, String did)? awaitingApproval,
    TResult Function(Uint8List ringId)? done,
    TResult Function(String reason)? failed,
    required TResult orElse(),
  }) {
    if (awaitingApproval != null) {
      return awaitingApproval(deviceName, did);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(PairingUiStateDto_Idle value) idle,
    required TResult Function(PairingUiStateDto_ShowingCode value) showingCode,
    required TResult Function(PairingUiStateDto_AwaitingPeer value)
        awaitingPeer,
    required TResult Function(PairingUiStateDto_AwaitingApproval value)
        awaitingApproval,
    required TResult Function(PairingUiStateDto_Done value) done,
    required TResult Function(PairingUiStateDto_Failed value) failed,
  }) {
    return awaitingApproval(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(PairingUiStateDto_Idle value)? idle,
    TResult? Function(PairingUiStateDto_ShowingCode value)? showingCode,
    TResult? Function(PairingUiStateDto_AwaitingPeer value)? awaitingPeer,
    TResult? Function(PairingUiStateDto_AwaitingApproval value)?
        awaitingApproval,
    TResult? Function(PairingUiStateDto_Done value)? done,
    TResult? Function(PairingUiStateDto_Failed value)? failed,
  }) {
    return awaitingApproval?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(PairingUiStateDto_Idle value)? idle,
    TResult Function(PairingUiStateDto_ShowingCode value)? showingCode,
    TResult Function(PairingUiStateDto_AwaitingPeer value)? awaitingPeer,
    TResult Function(PairingUiStateDto_AwaitingApproval value)?
        awaitingApproval,
    TResult Function(PairingUiStateDto_Done value)? done,
    TResult Function(PairingUiStateDto_Failed value)? failed,
    required TResult orElse(),
  }) {
    if (awaitingApproval != null) {
      return awaitingApproval(this);
    }
    return orElse();
  }
}

abstract class PairingUiStateDto_AwaitingApproval extends PairingUiStateDto {
  const factory PairingUiStateDto_AwaitingApproval(
      {required final String deviceName,
      required final String did}) = _$PairingUiStateDto_AwaitingApprovalImpl;
  const PairingUiStateDto_AwaitingApproval._() : super._();

  String get deviceName;
  String get did;

  /// Create a copy of PairingUiStateDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$PairingUiStateDto_AwaitingApprovalImplCopyWith<
          _$PairingUiStateDto_AwaitingApprovalImpl>
      get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$PairingUiStateDto_DoneImplCopyWith<$Res> {
  factory _$$PairingUiStateDto_DoneImplCopyWith(
          _$PairingUiStateDto_DoneImpl value,
          $Res Function(_$PairingUiStateDto_DoneImpl) then) =
      __$$PairingUiStateDto_DoneImplCopyWithImpl<$Res>;
  @useResult
  $Res call({Uint8List ringId});
}

/// @nodoc
class __$$PairingUiStateDto_DoneImplCopyWithImpl<$Res>
    extends _$PairingUiStateDtoCopyWithImpl<$Res, _$PairingUiStateDto_DoneImpl>
    implements _$$PairingUiStateDto_DoneImplCopyWith<$Res> {
  __$$PairingUiStateDto_DoneImplCopyWithImpl(
      _$PairingUiStateDto_DoneImpl _value,
      $Res Function(_$PairingUiStateDto_DoneImpl) _then)
      : super(_value, _then);

  /// Create a copy of PairingUiStateDto
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? ringId = null,
  }) {
    return _then(_$PairingUiStateDto_DoneImpl(
      ringId: null == ringId
          ? _value.ringId
          : ringId // ignore: cast_nullable_to_non_nullable
              as Uint8List,
    ));
  }
}

/// @nodoc

class _$PairingUiStateDto_DoneImpl extends PairingUiStateDto_Done {
  const _$PairingUiStateDto_DoneImpl({required this.ringId}) : super._();

  @override
  final Uint8List ringId;

  @override
  String toString() {
    return 'PairingUiStateDto.done(ringId: $ringId)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$PairingUiStateDto_DoneImpl &&
            const DeepCollectionEquality().equals(other.ringId, ringId));
  }

  @override
  int get hashCode =>
      Object.hash(runtimeType, const DeepCollectionEquality().hash(ringId));

  /// Create a copy of PairingUiStateDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$PairingUiStateDto_DoneImplCopyWith<_$PairingUiStateDto_DoneImpl>
      get copyWith => __$$PairingUiStateDto_DoneImplCopyWithImpl<
          _$PairingUiStateDto_DoneImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() idle,
    required TResult Function(String code, String drawbridgeUrl, String uri)
        showingCode,
    required TResult Function() awaitingPeer,
    required TResult Function(String deviceName, String did) awaitingApproval,
    required TResult Function(Uint8List ringId) done,
    required TResult Function(String reason) failed,
  }) {
    return done(ringId);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function()? idle,
    TResult? Function(String code, String drawbridgeUrl, String uri)?
        showingCode,
    TResult? Function()? awaitingPeer,
    TResult? Function(String deviceName, String did)? awaitingApproval,
    TResult? Function(Uint8List ringId)? done,
    TResult? Function(String reason)? failed,
  }) {
    return done?.call(ringId);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? idle,
    TResult Function(String code, String drawbridgeUrl, String uri)?
        showingCode,
    TResult Function()? awaitingPeer,
    TResult Function(String deviceName, String did)? awaitingApproval,
    TResult Function(Uint8List ringId)? done,
    TResult Function(String reason)? failed,
    required TResult orElse(),
  }) {
    if (done != null) {
      return done(ringId);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(PairingUiStateDto_Idle value) idle,
    required TResult Function(PairingUiStateDto_ShowingCode value) showingCode,
    required TResult Function(PairingUiStateDto_AwaitingPeer value)
        awaitingPeer,
    required TResult Function(PairingUiStateDto_AwaitingApproval value)
        awaitingApproval,
    required TResult Function(PairingUiStateDto_Done value) done,
    required TResult Function(PairingUiStateDto_Failed value) failed,
  }) {
    return done(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(PairingUiStateDto_Idle value)? idle,
    TResult? Function(PairingUiStateDto_ShowingCode value)? showingCode,
    TResult? Function(PairingUiStateDto_AwaitingPeer value)? awaitingPeer,
    TResult? Function(PairingUiStateDto_AwaitingApproval value)?
        awaitingApproval,
    TResult? Function(PairingUiStateDto_Done value)? done,
    TResult? Function(PairingUiStateDto_Failed value)? failed,
  }) {
    return done?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(PairingUiStateDto_Idle value)? idle,
    TResult Function(PairingUiStateDto_ShowingCode value)? showingCode,
    TResult Function(PairingUiStateDto_AwaitingPeer value)? awaitingPeer,
    TResult Function(PairingUiStateDto_AwaitingApproval value)?
        awaitingApproval,
    TResult Function(PairingUiStateDto_Done value)? done,
    TResult Function(PairingUiStateDto_Failed value)? failed,
    required TResult orElse(),
  }) {
    if (done != null) {
      return done(this);
    }
    return orElse();
  }
}

abstract class PairingUiStateDto_Done extends PairingUiStateDto {
  const factory PairingUiStateDto_Done({required final Uint8List ringId}) =
      _$PairingUiStateDto_DoneImpl;
  const PairingUiStateDto_Done._() : super._();

  Uint8List get ringId;

  /// Create a copy of PairingUiStateDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$PairingUiStateDto_DoneImplCopyWith<_$PairingUiStateDto_DoneImpl>
      get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$PairingUiStateDto_FailedImplCopyWith<$Res> {
  factory _$$PairingUiStateDto_FailedImplCopyWith(
          _$PairingUiStateDto_FailedImpl value,
          $Res Function(_$PairingUiStateDto_FailedImpl) then) =
      __$$PairingUiStateDto_FailedImplCopyWithImpl<$Res>;
  @useResult
  $Res call({String reason});
}

/// @nodoc
class __$$PairingUiStateDto_FailedImplCopyWithImpl<$Res>
    extends _$PairingUiStateDtoCopyWithImpl<$Res,
        _$PairingUiStateDto_FailedImpl>
    implements _$$PairingUiStateDto_FailedImplCopyWith<$Res> {
  __$$PairingUiStateDto_FailedImplCopyWithImpl(
      _$PairingUiStateDto_FailedImpl _value,
      $Res Function(_$PairingUiStateDto_FailedImpl) _then)
      : super(_value, _then);

  /// Create a copy of PairingUiStateDto
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? reason = null,
  }) {
    return _then(_$PairingUiStateDto_FailedImpl(
      reason: null == reason
          ? _value.reason
          : reason // ignore: cast_nullable_to_non_nullable
              as String,
    ));
  }
}

/// @nodoc

class _$PairingUiStateDto_FailedImpl extends PairingUiStateDto_Failed {
  const _$PairingUiStateDto_FailedImpl({required this.reason}) : super._();

  @override
  final String reason;

  @override
  String toString() {
    return 'PairingUiStateDto.failed(reason: $reason)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$PairingUiStateDto_FailedImpl &&
            (identical(other.reason, reason) || other.reason == reason));
  }

  @override
  int get hashCode => Object.hash(runtimeType, reason);

  /// Create a copy of PairingUiStateDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$PairingUiStateDto_FailedImplCopyWith<_$PairingUiStateDto_FailedImpl>
      get copyWith => __$$PairingUiStateDto_FailedImplCopyWithImpl<
          _$PairingUiStateDto_FailedImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() idle,
    required TResult Function(String code, String drawbridgeUrl, String uri)
        showingCode,
    required TResult Function() awaitingPeer,
    required TResult Function(String deviceName, String did) awaitingApproval,
    required TResult Function(Uint8List ringId) done,
    required TResult Function(String reason) failed,
  }) {
    return failed(reason);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function()? idle,
    TResult? Function(String code, String drawbridgeUrl, String uri)?
        showingCode,
    TResult? Function()? awaitingPeer,
    TResult? Function(String deviceName, String did)? awaitingApproval,
    TResult? Function(Uint8List ringId)? done,
    TResult? Function(String reason)? failed,
  }) {
    return failed?.call(reason);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? idle,
    TResult Function(String code, String drawbridgeUrl, String uri)?
        showingCode,
    TResult Function()? awaitingPeer,
    TResult Function(String deviceName, String did)? awaitingApproval,
    TResult Function(Uint8List ringId)? done,
    TResult Function(String reason)? failed,
    required TResult orElse(),
  }) {
    if (failed != null) {
      return failed(reason);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(PairingUiStateDto_Idle value) idle,
    required TResult Function(PairingUiStateDto_ShowingCode value) showingCode,
    required TResult Function(PairingUiStateDto_AwaitingPeer value)
        awaitingPeer,
    required TResult Function(PairingUiStateDto_AwaitingApproval value)
        awaitingApproval,
    required TResult Function(PairingUiStateDto_Done value) done,
    required TResult Function(PairingUiStateDto_Failed value) failed,
  }) {
    return failed(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(PairingUiStateDto_Idle value)? idle,
    TResult? Function(PairingUiStateDto_ShowingCode value)? showingCode,
    TResult? Function(PairingUiStateDto_AwaitingPeer value)? awaitingPeer,
    TResult? Function(PairingUiStateDto_AwaitingApproval value)?
        awaitingApproval,
    TResult? Function(PairingUiStateDto_Done value)? done,
    TResult? Function(PairingUiStateDto_Failed value)? failed,
  }) {
    return failed?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(PairingUiStateDto_Idle value)? idle,
    TResult Function(PairingUiStateDto_ShowingCode value)? showingCode,
    TResult Function(PairingUiStateDto_AwaitingPeer value)? awaitingPeer,
    TResult Function(PairingUiStateDto_AwaitingApproval value)?
        awaitingApproval,
    TResult Function(PairingUiStateDto_Done value)? done,
    TResult Function(PairingUiStateDto_Failed value)? failed,
    required TResult orElse(),
  }) {
    if (failed != null) {
      return failed(this);
    }
    return orElse();
  }
}

abstract class PairingUiStateDto_Failed extends PairingUiStateDto {
  const factory PairingUiStateDto_Failed({required final String reason}) =
      _$PairingUiStateDto_FailedImpl;
  const PairingUiStateDto_Failed._() : super._();

  String get reason;

  /// Create a copy of PairingUiStateDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$PairingUiStateDto_FailedImplCopyWith<_$PairingUiStateDto_FailedImpl>
      get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
mixin _$RingCommandDto {
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(Uint8List tag, Uint8List ciphertext)
        publishStealthEvent,
    required TResult Function() replenishKeyPackage,
    required TResult Function(Uint8List groupId, GroupKindDto kind)
        registerGroup,
    required TResult Function() pollForNewDevices,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(Uint8List tag, Uint8List ciphertext)? publishStealthEvent,
    TResult? Function()? replenishKeyPackage,
    TResult? Function(Uint8List groupId, GroupKindDto kind)? registerGroup,
    TResult? Function()? pollForNewDevices,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(Uint8List tag, Uint8List ciphertext)? publishStealthEvent,
    TResult Function()? replenishKeyPackage,
    TResult Function(Uint8List groupId, GroupKindDto kind)? registerGroup,
    TResult Function()? pollForNewDevices,
    required TResult orElse(),
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(RingCommandDto_PublishStealthEvent value)
        publishStealthEvent,
    required TResult Function(RingCommandDto_ReplenishKeyPackage value)
        replenishKeyPackage,
    required TResult Function(RingCommandDto_RegisterGroup value) registerGroup,
    required TResult Function(RingCommandDto_PollForNewDevices value)
        pollForNewDevices,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(RingCommandDto_PublishStealthEvent value)?
        publishStealthEvent,
    TResult? Function(RingCommandDto_ReplenishKeyPackage value)?
        replenishKeyPackage,
    TResult? Function(RingCommandDto_RegisterGroup value)? registerGroup,
    TResult? Function(RingCommandDto_PollForNewDevices value)?
        pollForNewDevices,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(RingCommandDto_PublishStealthEvent value)?
        publishStealthEvent,
    TResult Function(RingCommandDto_ReplenishKeyPackage value)?
        replenishKeyPackage,
    TResult Function(RingCommandDto_RegisterGroup value)? registerGroup,
    TResult Function(RingCommandDto_PollForNewDevices value)? pollForNewDevices,
    required TResult orElse(),
  }) =>
      throw _privateConstructorUsedError;
}

/// @nodoc
abstract class $RingCommandDtoCopyWith<$Res> {
  factory $RingCommandDtoCopyWith(
          RingCommandDto value, $Res Function(RingCommandDto) then) =
      _$RingCommandDtoCopyWithImpl<$Res, RingCommandDto>;
}

/// @nodoc
class _$RingCommandDtoCopyWithImpl<$Res, $Val extends RingCommandDto>
    implements $RingCommandDtoCopyWith<$Res> {
  _$RingCommandDtoCopyWithImpl(this._value, this._then);

  // ignore: unused_field
  final $Val _value;
  // ignore: unused_field
  final $Res Function($Val) _then;

  /// Create a copy of RingCommandDto
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc
abstract class _$$RingCommandDto_PublishStealthEventImplCopyWith<$Res> {
  factory _$$RingCommandDto_PublishStealthEventImplCopyWith(
          _$RingCommandDto_PublishStealthEventImpl value,
          $Res Function(_$RingCommandDto_PublishStealthEventImpl) then) =
      __$$RingCommandDto_PublishStealthEventImplCopyWithImpl<$Res>;
  @useResult
  $Res call({Uint8List tag, Uint8List ciphertext});
}

/// @nodoc
class __$$RingCommandDto_PublishStealthEventImplCopyWithImpl<$Res>
    extends _$RingCommandDtoCopyWithImpl<$Res,
        _$RingCommandDto_PublishStealthEventImpl>
    implements _$$RingCommandDto_PublishStealthEventImplCopyWith<$Res> {
  __$$RingCommandDto_PublishStealthEventImplCopyWithImpl(
      _$RingCommandDto_PublishStealthEventImpl _value,
      $Res Function(_$RingCommandDto_PublishStealthEventImpl) _then)
      : super(_value, _then);

  /// Create a copy of RingCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? tag = null,
    Object? ciphertext = null,
  }) {
    return _then(_$RingCommandDto_PublishStealthEventImpl(
      tag: null == tag
          ? _value.tag
          : tag // ignore: cast_nullable_to_non_nullable
              as Uint8List,
      ciphertext: null == ciphertext
          ? _value.ciphertext
          : ciphertext // ignore: cast_nullable_to_non_nullable
              as Uint8List,
    ));
  }
}

/// @nodoc

class _$RingCommandDto_PublishStealthEventImpl
    extends RingCommandDto_PublishStealthEvent {
  const _$RingCommandDto_PublishStealthEventImpl(
      {required this.tag, required this.ciphertext})
      : super._();

  @override
  final Uint8List tag;
  @override
  final Uint8List ciphertext;

  @override
  String toString() {
    return 'RingCommandDto.publishStealthEvent(tag: $tag, ciphertext: $ciphertext)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$RingCommandDto_PublishStealthEventImpl &&
            const DeepCollectionEquality().equals(other.tag, tag) &&
            const DeepCollectionEquality()
                .equals(other.ciphertext, ciphertext));
  }

  @override
  int get hashCode => Object.hash(
      runtimeType,
      const DeepCollectionEquality().hash(tag),
      const DeepCollectionEquality().hash(ciphertext));

  /// Create a copy of RingCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$RingCommandDto_PublishStealthEventImplCopyWith<
          _$RingCommandDto_PublishStealthEventImpl>
      get copyWith => __$$RingCommandDto_PublishStealthEventImplCopyWithImpl<
          _$RingCommandDto_PublishStealthEventImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(Uint8List tag, Uint8List ciphertext)
        publishStealthEvent,
    required TResult Function() replenishKeyPackage,
    required TResult Function(Uint8List groupId, GroupKindDto kind)
        registerGroup,
    required TResult Function() pollForNewDevices,
  }) {
    return publishStealthEvent(tag, ciphertext);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(Uint8List tag, Uint8List ciphertext)? publishStealthEvent,
    TResult? Function()? replenishKeyPackage,
    TResult? Function(Uint8List groupId, GroupKindDto kind)? registerGroup,
    TResult? Function()? pollForNewDevices,
  }) {
    return publishStealthEvent?.call(tag, ciphertext);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(Uint8List tag, Uint8List ciphertext)? publishStealthEvent,
    TResult Function()? replenishKeyPackage,
    TResult Function(Uint8List groupId, GroupKindDto kind)? registerGroup,
    TResult Function()? pollForNewDevices,
    required TResult orElse(),
  }) {
    if (publishStealthEvent != null) {
      return publishStealthEvent(tag, ciphertext);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(RingCommandDto_PublishStealthEvent value)
        publishStealthEvent,
    required TResult Function(RingCommandDto_ReplenishKeyPackage value)
        replenishKeyPackage,
    required TResult Function(RingCommandDto_RegisterGroup value) registerGroup,
    required TResult Function(RingCommandDto_PollForNewDevices value)
        pollForNewDevices,
  }) {
    return publishStealthEvent(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(RingCommandDto_PublishStealthEvent value)?
        publishStealthEvent,
    TResult? Function(RingCommandDto_ReplenishKeyPackage value)?
        replenishKeyPackage,
    TResult? Function(RingCommandDto_RegisterGroup value)? registerGroup,
    TResult? Function(RingCommandDto_PollForNewDevices value)?
        pollForNewDevices,
  }) {
    return publishStealthEvent?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(RingCommandDto_PublishStealthEvent value)?
        publishStealthEvent,
    TResult Function(RingCommandDto_ReplenishKeyPackage value)?
        replenishKeyPackage,
    TResult Function(RingCommandDto_RegisterGroup value)? registerGroup,
    TResult Function(RingCommandDto_PollForNewDevices value)? pollForNewDevices,
    required TResult orElse(),
  }) {
    if (publishStealthEvent != null) {
      return publishStealthEvent(this);
    }
    return orElse();
  }
}

abstract class RingCommandDto_PublishStealthEvent extends RingCommandDto {
  const factory RingCommandDto_PublishStealthEvent(
          {required final Uint8List tag, required final Uint8List ciphertext}) =
      _$RingCommandDto_PublishStealthEventImpl;
  const RingCommandDto_PublishStealthEvent._() : super._();

  Uint8List get tag;
  Uint8List get ciphertext;

  /// Create a copy of RingCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$RingCommandDto_PublishStealthEventImplCopyWith<
          _$RingCommandDto_PublishStealthEventImpl>
      get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$RingCommandDto_ReplenishKeyPackageImplCopyWith<$Res> {
  factory _$$RingCommandDto_ReplenishKeyPackageImplCopyWith(
          _$RingCommandDto_ReplenishKeyPackageImpl value,
          $Res Function(_$RingCommandDto_ReplenishKeyPackageImpl) then) =
      __$$RingCommandDto_ReplenishKeyPackageImplCopyWithImpl<$Res>;
}

/// @nodoc
class __$$RingCommandDto_ReplenishKeyPackageImplCopyWithImpl<$Res>
    extends _$RingCommandDtoCopyWithImpl<$Res,
        _$RingCommandDto_ReplenishKeyPackageImpl>
    implements _$$RingCommandDto_ReplenishKeyPackageImplCopyWith<$Res> {
  __$$RingCommandDto_ReplenishKeyPackageImplCopyWithImpl(
      _$RingCommandDto_ReplenishKeyPackageImpl _value,
      $Res Function(_$RingCommandDto_ReplenishKeyPackageImpl) _then)
      : super(_value, _then);

  /// Create a copy of RingCommandDto
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc

class _$RingCommandDto_ReplenishKeyPackageImpl
    extends RingCommandDto_ReplenishKeyPackage {
  const _$RingCommandDto_ReplenishKeyPackageImpl() : super._();

  @override
  String toString() {
    return 'RingCommandDto.replenishKeyPackage()';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$RingCommandDto_ReplenishKeyPackageImpl);
  }

  @override
  int get hashCode => runtimeType.hashCode;

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(Uint8List tag, Uint8List ciphertext)
        publishStealthEvent,
    required TResult Function() replenishKeyPackage,
    required TResult Function(Uint8List groupId, GroupKindDto kind)
        registerGroup,
    required TResult Function() pollForNewDevices,
  }) {
    return replenishKeyPackage();
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(Uint8List tag, Uint8List ciphertext)? publishStealthEvent,
    TResult? Function()? replenishKeyPackage,
    TResult? Function(Uint8List groupId, GroupKindDto kind)? registerGroup,
    TResult? Function()? pollForNewDevices,
  }) {
    return replenishKeyPackage?.call();
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(Uint8List tag, Uint8List ciphertext)? publishStealthEvent,
    TResult Function()? replenishKeyPackage,
    TResult Function(Uint8List groupId, GroupKindDto kind)? registerGroup,
    TResult Function()? pollForNewDevices,
    required TResult orElse(),
  }) {
    if (replenishKeyPackage != null) {
      return replenishKeyPackage();
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(RingCommandDto_PublishStealthEvent value)
        publishStealthEvent,
    required TResult Function(RingCommandDto_ReplenishKeyPackage value)
        replenishKeyPackage,
    required TResult Function(RingCommandDto_RegisterGroup value) registerGroup,
    required TResult Function(RingCommandDto_PollForNewDevices value)
        pollForNewDevices,
  }) {
    return replenishKeyPackage(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(RingCommandDto_PublishStealthEvent value)?
        publishStealthEvent,
    TResult? Function(RingCommandDto_ReplenishKeyPackage value)?
        replenishKeyPackage,
    TResult? Function(RingCommandDto_RegisterGroup value)? registerGroup,
    TResult? Function(RingCommandDto_PollForNewDevices value)?
        pollForNewDevices,
  }) {
    return replenishKeyPackage?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(RingCommandDto_PublishStealthEvent value)?
        publishStealthEvent,
    TResult Function(RingCommandDto_ReplenishKeyPackage value)?
        replenishKeyPackage,
    TResult Function(RingCommandDto_RegisterGroup value)? registerGroup,
    TResult Function(RingCommandDto_PollForNewDevices value)? pollForNewDevices,
    required TResult orElse(),
  }) {
    if (replenishKeyPackage != null) {
      return replenishKeyPackage(this);
    }
    return orElse();
  }
}

abstract class RingCommandDto_ReplenishKeyPackage extends RingCommandDto {
  const factory RingCommandDto_ReplenishKeyPackage() =
      _$RingCommandDto_ReplenishKeyPackageImpl;
  const RingCommandDto_ReplenishKeyPackage._() : super._();
}

/// @nodoc
abstract class _$$RingCommandDto_RegisterGroupImplCopyWith<$Res> {
  factory _$$RingCommandDto_RegisterGroupImplCopyWith(
          _$RingCommandDto_RegisterGroupImpl value,
          $Res Function(_$RingCommandDto_RegisterGroupImpl) then) =
      __$$RingCommandDto_RegisterGroupImplCopyWithImpl<$Res>;
  @useResult
  $Res call({Uint8List groupId, GroupKindDto kind});
}

/// @nodoc
class __$$RingCommandDto_RegisterGroupImplCopyWithImpl<$Res>
    extends _$RingCommandDtoCopyWithImpl<$Res,
        _$RingCommandDto_RegisterGroupImpl>
    implements _$$RingCommandDto_RegisterGroupImplCopyWith<$Res> {
  __$$RingCommandDto_RegisterGroupImplCopyWithImpl(
      _$RingCommandDto_RegisterGroupImpl _value,
      $Res Function(_$RingCommandDto_RegisterGroupImpl) _then)
      : super(_value, _then);

  /// Create a copy of RingCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? groupId = null,
    Object? kind = null,
  }) {
    return _then(_$RingCommandDto_RegisterGroupImpl(
      groupId: null == groupId
          ? _value.groupId
          : groupId // ignore: cast_nullable_to_non_nullable
              as Uint8List,
      kind: null == kind
          ? _value.kind
          : kind // ignore: cast_nullable_to_non_nullable
              as GroupKindDto,
    ));
  }
}

/// @nodoc

class _$RingCommandDto_RegisterGroupImpl extends RingCommandDto_RegisterGroup {
  const _$RingCommandDto_RegisterGroupImpl(
      {required this.groupId, required this.kind})
      : super._();

  @override
  final Uint8List groupId;
  @override
  final GroupKindDto kind;

  @override
  String toString() {
    return 'RingCommandDto.registerGroup(groupId: $groupId, kind: $kind)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$RingCommandDto_RegisterGroupImpl &&
            const DeepCollectionEquality().equals(other.groupId, groupId) &&
            (identical(other.kind, kind) || other.kind == kind));
  }

  @override
  int get hashCode => Object.hash(
      runtimeType, const DeepCollectionEquality().hash(groupId), kind);

  /// Create a copy of RingCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$RingCommandDto_RegisterGroupImplCopyWith<
          _$RingCommandDto_RegisterGroupImpl>
      get copyWith => __$$RingCommandDto_RegisterGroupImplCopyWithImpl<
          _$RingCommandDto_RegisterGroupImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(Uint8List tag, Uint8List ciphertext)
        publishStealthEvent,
    required TResult Function() replenishKeyPackage,
    required TResult Function(Uint8List groupId, GroupKindDto kind)
        registerGroup,
    required TResult Function() pollForNewDevices,
  }) {
    return registerGroup(groupId, kind);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(Uint8List tag, Uint8List ciphertext)? publishStealthEvent,
    TResult? Function()? replenishKeyPackage,
    TResult? Function(Uint8List groupId, GroupKindDto kind)? registerGroup,
    TResult? Function()? pollForNewDevices,
  }) {
    return registerGroup?.call(groupId, kind);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(Uint8List tag, Uint8List ciphertext)? publishStealthEvent,
    TResult Function()? replenishKeyPackage,
    TResult Function(Uint8List groupId, GroupKindDto kind)? registerGroup,
    TResult Function()? pollForNewDevices,
    required TResult orElse(),
  }) {
    if (registerGroup != null) {
      return registerGroup(groupId, kind);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(RingCommandDto_PublishStealthEvent value)
        publishStealthEvent,
    required TResult Function(RingCommandDto_ReplenishKeyPackage value)
        replenishKeyPackage,
    required TResult Function(RingCommandDto_RegisterGroup value) registerGroup,
    required TResult Function(RingCommandDto_PollForNewDevices value)
        pollForNewDevices,
  }) {
    return registerGroup(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(RingCommandDto_PublishStealthEvent value)?
        publishStealthEvent,
    TResult? Function(RingCommandDto_ReplenishKeyPackage value)?
        replenishKeyPackage,
    TResult? Function(RingCommandDto_RegisterGroup value)? registerGroup,
    TResult? Function(RingCommandDto_PollForNewDevices value)?
        pollForNewDevices,
  }) {
    return registerGroup?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(RingCommandDto_PublishStealthEvent value)?
        publishStealthEvent,
    TResult Function(RingCommandDto_ReplenishKeyPackage value)?
        replenishKeyPackage,
    TResult Function(RingCommandDto_RegisterGroup value)? registerGroup,
    TResult Function(RingCommandDto_PollForNewDevices value)? pollForNewDevices,
    required TResult orElse(),
  }) {
    if (registerGroup != null) {
      return registerGroup(this);
    }
    return orElse();
  }
}

abstract class RingCommandDto_RegisterGroup extends RingCommandDto {
  const factory RingCommandDto_RegisterGroup(
      {required final Uint8List groupId,
      required final GroupKindDto kind}) = _$RingCommandDto_RegisterGroupImpl;
  const RingCommandDto_RegisterGroup._() : super._();

  Uint8List get groupId;
  GroupKindDto get kind;

  /// Create a copy of RingCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$RingCommandDto_RegisterGroupImplCopyWith<
          _$RingCommandDto_RegisterGroupImpl>
      get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$RingCommandDto_PollForNewDevicesImplCopyWith<$Res> {
  factory _$$RingCommandDto_PollForNewDevicesImplCopyWith(
          _$RingCommandDto_PollForNewDevicesImpl value,
          $Res Function(_$RingCommandDto_PollForNewDevicesImpl) then) =
      __$$RingCommandDto_PollForNewDevicesImplCopyWithImpl<$Res>;
}

/// @nodoc
class __$$RingCommandDto_PollForNewDevicesImplCopyWithImpl<$Res>
    extends _$RingCommandDtoCopyWithImpl<$Res,
        _$RingCommandDto_PollForNewDevicesImpl>
    implements _$$RingCommandDto_PollForNewDevicesImplCopyWith<$Res> {
  __$$RingCommandDto_PollForNewDevicesImplCopyWithImpl(
      _$RingCommandDto_PollForNewDevicesImpl _value,
      $Res Function(_$RingCommandDto_PollForNewDevicesImpl) _then)
      : super(_value, _then);

  /// Create a copy of RingCommandDto
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc

class _$RingCommandDto_PollForNewDevicesImpl
    extends RingCommandDto_PollForNewDevices {
  const _$RingCommandDto_PollForNewDevicesImpl() : super._();

  @override
  String toString() {
    return 'RingCommandDto.pollForNewDevices()';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$RingCommandDto_PollForNewDevicesImpl);
  }

  @override
  int get hashCode => runtimeType.hashCode;

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(Uint8List tag, Uint8List ciphertext)
        publishStealthEvent,
    required TResult Function() replenishKeyPackage,
    required TResult Function(Uint8List groupId, GroupKindDto kind)
        registerGroup,
    required TResult Function() pollForNewDevices,
  }) {
    return pollForNewDevices();
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(Uint8List tag, Uint8List ciphertext)? publishStealthEvent,
    TResult? Function()? replenishKeyPackage,
    TResult? Function(Uint8List groupId, GroupKindDto kind)? registerGroup,
    TResult? Function()? pollForNewDevices,
  }) {
    return pollForNewDevices?.call();
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(Uint8List tag, Uint8List ciphertext)? publishStealthEvent,
    TResult Function()? replenishKeyPackage,
    TResult Function(Uint8List groupId, GroupKindDto kind)? registerGroup,
    TResult Function()? pollForNewDevices,
    required TResult orElse(),
  }) {
    if (pollForNewDevices != null) {
      return pollForNewDevices();
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(RingCommandDto_PublishStealthEvent value)
        publishStealthEvent,
    required TResult Function(RingCommandDto_ReplenishKeyPackage value)
        replenishKeyPackage,
    required TResult Function(RingCommandDto_RegisterGroup value) registerGroup,
    required TResult Function(RingCommandDto_PollForNewDevices value)
        pollForNewDevices,
  }) {
    return pollForNewDevices(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(RingCommandDto_PublishStealthEvent value)?
        publishStealthEvent,
    TResult? Function(RingCommandDto_ReplenishKeyPackage value)?
        replenishKeyPackage,
    TResult? Function(RingCommandDto_RegisterGroup value)? registerGroup,
    TResult? Function(RingCommandDto_PollForNewDevices value)?
        pollForNewDevices,
  }) {
    return pollForNewDevices?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(RingCommandDto_PublishStealthEvent value)?
        publishStealthEvent,
    TResult Function(RingCommandDto_ReplenishKeyPackage value)?
        replenishKeyPackage,
    TResult Function(RingCommandDto_RegisterGroup value)? registerGroup,
    TResult Function(RingCommandDto_PollForNewDevices value)? pollForNewDevices,
    required TResult orElse(),
  }) {
    if (pollForNewDevices != null) {
      return pollForNewDevices(this);
    }
    return orElse();
  }
}

abstract class RingCommandDto_PollForNewDevices extends RingCommandDto {
  const factory RingCommandDto_PollForNewDevices() =
      _$RingCommandDto_PollForNewDevicesImpl;
  const RingCommandDto_PollForNewDevices._() : super._();
}

/// @nodoc
mixin _$SyncFailureDto {
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() noAnswer,
    required TResult Function() requestExpired,
    required TResult Function() declined,
    required TResult Function(String detail) channelClosed,
    required TResult Function(String detail) publishFailed,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function()? noAnswer,
    TResult? Function()? requestExpired,
    TResult? Function()? declined,
    TResult? Function(String detail)? channelClosed,
    TResult? Function(String detail)? publishFailed,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? noAnswer,
    TResult Function()? requestExpired,
    TResult Function()? declined,
    TResult Function(String detail)? channelClosed,
    TResult Function(String detail)? publishFailed,
    required TResult orElse(),
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(SyncFailureDto_NoAnswer value) noAnswer,
    required TResult Function(SyncFailureDto_RequestExpired value)
        requestExpired,
    required TResult Function(SyncFailureDto_Declined value) declined,
    required TResult Function(SyncFailureDto_ChannelClosed value) channelClosed,
    required TResult Function(SyncFailureDto_PublishFailed value) publishFailed,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(SyncFailureDto_NoAnswer value)? noAnswer,
    TResult? Function(SyncFailureDto_RequestExpired value)? requestExpired,
    TResult? Function(SyncFailureDto_Declined value)? declined,
    TResult? Function(SyncFailureDto_ChannelClosed value)? channelClosed,
    TResult? Function(SyncFailureDto_PublishFailed value)? publishFailed,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(SyncFailureDto_NoAnswer value)? noAnswer,
    TResult Function(SyncFailureDto_RequestExpired value)? requestExpired,
    TResult Function(SyncFailureDto_Declined value)? declined,
    TResult Function(SyncFailureDto_ChannelClosed value)? channelClosed,
    TResult Function(SyncFailureDto_PublishFailed value)? publishFailed,
    required TResult orElse(),
  }) =>
      throw _privateConstructorUsedError;
}

/// @nodoc
abstract class $SyncFailureDtoCopyWith<$Res> {
  factory $SyncFailureDtoCopyWith(
          SyncFailureDto value, $Res Function(SyncFailureDto) then) =
      _$SyncFailureDtoCopyWithImpl<$Res, SyncFailureDto>;
}

/// @nodoc
class _$SyncFailureDtoCopyWithImpl<$Res, $Val extends SyncFailureDto>
    implements $SyncFailureDtoCopyWith<$Res> {
  _$SyncFailureDtoCopyWithImpl(this._value, this._then);

  // ignore: unused_field
  final $Val _value;
  // ignore: unused_field
  final $Res Function($Val) _then;

  /// Create a copy of SyncFailureDto
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc
abstract class _$$SyncFailureDto_NoAnswerImplCopyWith<$Res> {
  factory _$$SyncFailureDto_NoAnswerImplCopyWith(
          _$SyncFailureDto_NoAnswerImpl value,
          $Res Function(_$SyncFailureDto_NoAnswerImpl) then) =
      __$$SyncFailureDto_NoAnswerImplCopyWithImpl<$Res>;
}

/// @nodoc
class __$$SyncFailureDto_NoAnswerImplCopyWithImpl<$Res>
    extends _$SyncFailureDtoCopyWithImpl<$Res, _$SyncFailureDto_NoAnswerImpl>
    implements _$$SyncFailureDto_NoAnswerImplCopyWith<$Res> {
  __$$SyncFailureDto_NoAnswerImplCopyWithImpl(
      _$SyncFailureDto_NoAnswerImpl _value,
      $Res Function(_$SyncFailureDto_NoAnswerImpl) _then)
      : super(_value, _then);

  /// Create a copy of SyncFailureDto
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc

class _$SyncFailureDto_NoAnswerImpl extends SyncFailureDto_NoAnswer {
  const _$SyncFailureDto_NoAnswerImpl() : super._();

  @override
  String toString() {
    return 'SyncFailureDto.noAnswer()';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$SyncFailureDto_NoAnswerImpl);
  }

  @override
  int get hashCode => runtimeType.hashCode;

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() noAnswer,
    required TResult Function() requestExpired,
    required TResult Function() declined,
    required TResult Function(String detail) channelClosed,
    required TResult Function(String detail) publishFailed,
  }) {
    return noAnswer();
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function()? noAnswer,
    TResult? Function()? requestExpired,
    TResult? Function()? declined,
    TResult? Function(String detail)? channelClosed,
    TResult? Function(String detail)? publishFailed,
  }) {
    return noAnswer?.call();
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? noAnswer,
    TResult Function()? requestExpired,
    TResult Function()? declined,
    TResult Function(String detail)? channelClosed,
    TResult Function(String detail)? publishFailed,
    required TResult orElse(),
  }) {
    if (noAnswer != null) {
      return noAnswer();
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(SyncFailureDto_NoAnswer value) noAnswer,
    required TResult Function(SyncFailureDto_RequestExpired value)
        requestExpired,
    required TResult Function(SyncFailureDto_Declined value) declined,
    required TResult Function(SyncFailureDto_ChannelClosed value) channelClosed,
    required TResult Function(SyncFailureDto_PublishFailed value) publishFailed,
  }) {
    return noAnswer(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(SyncFailureDto_NoAnswer value)? noAnswer,
    TResult? Function(SyncFailureDto_RequestExpired value)? requestExpired,
    TResult? Function(SyncFailureDto_Declined value)? declined,
    TResult? Function(SyncFailureDto_ChannelClosed value)? channelClosed,
    TResult? Function(SyncFailureDto_PublishFailed value)? publishFailed,
  }) {
    return noAnswer?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(SyncFailureDto_NoAnswer value)? noAnswer,
    TResult Function(SyncFailureDto_RequestExpired value)? requestExpired,
    TResult Function(SyncFailureDto_Declined value)? declined,
    TResult Function(SyncFailureDto_ChannelClosed value)? channelClosed,
    TResult Function(SyncFailureDto_PublishFailed value)? publishFailed,
    required TResult orElse(),
  }) {
    if (noAnswer != null) {
      return noAnswer(this);
    }
    return orElse();
  }
}

abstract class SyncFailureDto_NoAnswer extends SyncFailureDto {
  const factory SyncFailureDto_NoAnswer() = _$SyncFailureDto_NoAnswerImpl;
  const SyncFailureDto_NoAnswer._() : super._();
}

/// @nodoc
abstract class _$$SyncFailureDto_RequestExpiredImplCopyWith<$Res> {
  factory _$$SyncFailureDto_RequestExpiredImplCopyWith(
          _$SyncFailureDto_RequestExpiredImpl value,
          $Res Function(_$SyncFailureDto_RequestExpiredImpl) then) =
      __$$SyncFailureDto_RequestExpiredImplCopyWithImpl<$Res>;
}

/// @nodoc
class __$$SyncFailureDto_RequestExpiredImplCopyWithImpl<$Res>
    extends _$SyncFailureDtoCopyWithImpl<$Res,
        _$SyncFailureDto_RequestExpiredImpl>
    implements _$$SyncFailureDto_RequestExpiredImplCopyWith<$Res> {
  __$$SyncFailureDto_RequestExpiredImplCopyWithImpl(
      _$SyncFailureDto_RequestExpiredImpl _value,
      $Res Function(_$SyncFailureDto_RequestExpiredImpl) _then)
      : super(_value, _then);

  /// Create a copy of SyncFailureDto
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc

class _$SyncFailureDto_RequestExpiredImpl
    extends SyncFailureDto_RequestExpired {
  const _$SyncFailureDto_RequestExpiredImpl() : super._();

  @override
  String toString() {
    return 'SyncFailureDto.requestExpired()';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$SyncFailureDto_RequestExpiredImpl);
  }

  @override
  int get hashCode => runtimeType.hashCode;

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() noAnswer,
    required TResult Function() requestExpired,
    required TResult Function() declined,
    required TResult Function(String detail) channelClosed,
    required TResult Function(String detail) publishFailed,
  }) {
    return requestExpired();
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function()? noAnswer,
    TResult? Function()? requestExpired,
    TResult? Function()? declined,
    TResult? Function(String detail)? channelClosed,
    TResult? Function(String detail)? publishFailed,
  }) {
    return requestExpired?.call();
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? noAnswer,
    TResult Function()? requestExpired,
    TResult Function()? declined,
    TResult Function(String detail)? channelClosed,
    TResult Function(String detail)? publishFailed,
    required TResult orElse(),
  }) {
    if (requestExpired != null) {
      return requestExpired();
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(SyncFailureDto_NoAnswer value) noAnswer,
    required TResult Function(SyncFailureDto_RequestExpired value)
        requestExpired,
    required TResult Function(SyncFailureDto_Declined value) declined,
    required TResult Function(SyncFailureDto_ChannelClosed value) channelClosed,
    required TResult Function(SyncFailureDto_PublishFailed value) publishFailed,
  }) {
    return requestExpired(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(SyncFailureDto_NoAnswer value)? noAnswer,
    TResult? Function(SyncFailureDto_RequestExpired value)? requestExpired,
    TResult? Function(SyncFailureDto_Declined value)? declined,
    TResult? Function(SyncFailureDto_ChannelClosed value)? channelClosed,
    TResult? Function(SyncFailureDto_PublishFailed value)? publishFailed,
  }) {
    return requestExpired?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(SyncFailureDto_NoAnswer value)? noAnswer,
    TResult Function(SyncFailureDto_RequestExpired value)? requestExpired,
    TResult Function(SyncFailureDto_Declined value)? declined,
    TResult Function(SyncFailureDto_ChannelClosed value)? channelClosed,
    TResult Function(SyncFailureDto_PublishFailed value)? publishFailed,
    required TResult orElse(),
  }) {
    if (requestExpired != null) {
      return requestExpired(this);
    }
    return orElse();
  }
}

abstract class SyncFailureDto_RequestExpired extends SyncFailureDto {
  const factory SyncFailureDto_RequestExpired() =
      _$SyncFailureDto_RequestExpiredImpl;
  const SyncFailureDto_RequestExpired._() : super._();
}

/// @nodoc
abstract class _$$SyncFailureDto_DeclinedImplCopyWith<$Res> {
  factory _$$SyncFailureDto_DeclinedImplCopyWith(
          _$SyncFailureDto_DeclinedImpl value,
          $Res Function(_$SyncFailureDto_DeclinedImpl) then) =
      __$$SyncFailureDto_DeclinedImplCopyWithImpl<$Res>;
}

/// @nodoc
class __$$SyncFailureDto_DeclinedImplCopyWithImpl<$Res>
    extends _$SyncFailureDtoCopyWithImpl<$Res, _$SyncFailureDto_DeclinedImpl>
    implements _$$SyncFailureDto_DeclinedImplCopyWith<$Res> {
  __$$SyncFailureDto_DeclinedImplCopyWithImpl(
      _$SyncFailureDto_DeclinedImpl _value,
      $Res Function(_$SyncFailureDto_DeclinedImpl) _then)
      : super(_value, _then);

  /// Create a copy of SyncFailureDto
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc

class _$SyncFailureDto_DeclinedImpl extends SyncFailureDto_Declined {
  const _$SyncFailureDto_DeclinedImpl() : super._();

  @override
  String toString() {
    return 'SyncFailureDto.declined()';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$SyncFailureDto_DeclinedImpl);
  }

  @override
  int get hashCode => runtimeType.hashCode;

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() noAnswer,
    required TResult Function() requestExpired,
    required TResult Function() declined,
    required TResult Function(String detail) channelClosed,
    required TResult Function(String detail) publishFailed,
  }) {
    return declined();
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function()? noAnswer,
    TResult? Function()? requestExpired,
    TResult? Function()? declined,
    TResult? Function(String detail)? channelClosed,
    TResult? Function(String detail)? publishFailed,
  }) {
    return declined?.call();
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? noAnswer,
    TResult Function()? requestExpired,
    TResult Function()? declined,
    TResult Function(String detail)? channelClosed,
    TResult Function(String detail)? publishFailed,
    required TResult orElse(),
  }) {
    if (declined != null) {
      return declined();
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(SyncFailureDto_NoAnswer value) noAnswer,
    required TResult Function(SyncFailureDto_RequestExpired value)
        requestExpired,
    required TResult Function(SyncFailureDto_Declined value) declined,
    required TResult Function(SyncFailureDto_ChannelClosed value) channelClosed,
    required TResult Function(SyncFailureDto_PublishFailed value) publishFailed,
  }) {
    return declined(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(SyncFailureDto_NoAnswer value)? noAnswer,
    TResult? Function(SyncFailureDto_RequestExpired value)? requestExpired,
    TResult? Function(SyncFailureDto_Declined value)? declined,
    TResult? Function(SyncFailureDto_ChannelClosed value)? channelClosed,
    TResult? Function(SyncFailureDto_PublishFailed value)? publishFailed,
  }) {
    return declined?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(SyncFailureDto_NoAnswer value)? noAnswer,
    TResult Function(SyncFailureDto_RequestExpired value)? requestExpired,
    TResult Function(SyncFailureDto_Declined value)? declined,
    TResult Function(SyncFailureDto_ChannelClosed value)? channelClosed,
    TResult Function(SyncFailureDto_PublishFailed value)? publishFailed,
    required TResult orElse(),
  }) {
    if (declined != null) {
      return declined(this);
    }
    return orElse();
  }
}

abstract class SyncFailureDto_Declined extends SyncFailureDto {
  const factory SyncFailureDto_Declined() = _$SyncFailureDto_DeclinedImpl;
  const SyncFailureDto_Declined._() : super._();
}

/// @nodoc
abstract class _$$SyncFailureDto_ChannelClosedImplCopyWith<$Res> {
  factory _$$SyncFailureDto_ChannelClosedImplCopyWith(
          _$SyncFailureDto_ChannelClosedImpl value,
          $Res Function(_$SyncFailureDto_ChannelClosedImpl) then) =
      __$$SyncFailureDto_ChannelClosedImplCopyWithImpl<$Res>;
  @useResult
  $Res call({String detail});
}

/// @nodoc
class __$$SyncFailureDto_ChannelClosedImplCopyWithImpl<$Res>
    extends _$SyncFailureDtoCopyWithImpl<$Res,
        _$SyncFailureDto_ChannelClosedImpl>
    implements _$$SyncFailureDto_ChannelClosedImplCopyWith<$Res> {
  __$$SyncFailureDto_ChannelClosedImplCopyWithImpl(
      _$SyncFailureDto_ChannelClosedImpl _value,
      $Res Function(_$SyncFailureDto_ChannelClosedImpl) _then)
      : super(_value, _then);

  /// Create a copy of SyncFailureDto
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? detail = null,
  }) {
    return _then(_$SyncFailureDto_ChannelClosedImpl(
      detail: null == detail
          ? _value.detail
          : detail // ignore: cast_nullable_to_non_nullable
              as String,
    ));
  }
}

/// @nodoc

class _$SyncFailureDto_ChannelClosedImpl extends SyncFailureDto_ChannelClosed {
  const _$SyncFailureDto_ChannelClosedImpl({required this.detail}) : super._();

  @override
  final String detail;

  @override
  String toString() {
    return 'SyncFailureDto.channelClosed(detail: $detail)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$SyncFailureDto_ChannelClosedImpl &&
            (identical(other.detail, detail) || other.detail == detail));
  }

  @override
  int get hashCode => Object.hash(runtimeType, detail);

  /// Create a copy of SyncFailureDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$SyncFailureDto_ChannelClosedImplCopyWith<
          _$SyncFailureDto_ChannelClosedImpl>
      get copyWith => __$$SyncFailureDto_ChannelClosedImplCopyWithImpl<
          _$SyncFailureDto_ChannelClosedImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() noAnswer,
    required TResult Function() requestExpired,
    required TResult Function() declined,
    required TResult Function(String detail) channelClosed,
    required TResult Function(String detail) publishFailed,
  }) {
    return channelClosed(detail);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function()? noAnswer,
    TResult? Function()? requestExpired,
    TResult? Function()? declined,
    TResult? Function(String detail)? channelClosed,
    TResult? Function(String detail)? publishFailed,
  }) {
    return channelClosed?.call(detail);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? noAnswer,
    TResult Function()? requestExpired,
    TResult Function()? declined,
    TResult Function(String detail)? channelClosed,
    TResult Function(String detail)? publishFailed,
    required TResult orElse(),
  }) {
    if (channelClosed != null) {
      return channelClosed(detail);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(SyncFailureDto_NoAnswer value) noAnswer,
    required TResult Function(SyncFailureDto_RequestExpired value)
        requestExpired,
    required TResult Function(SyncFailureDto_Declined value) declined,
    required TResult Function(SyncFailureDto_ChannelClosed value) channelClosed,
    required TResult Function(SyncFailureDto_PublishFailed value) publishFailed,
  }) {
    return channelClosed(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(SyncFailureDto_NoAnswer value)? noAnswer,
    TResult? Function(SyncFailureDto_RequestExpired value)? requestExpired,
    TResult? Function(SyncFailureDto_Declined value)? declined,
    TResult? Function(SyncFailureDto_ChannelClosed value)? channelClosed,
    TResult? Function(SyncFailureDto_PublishFailed value)? publishFailed,
  }) {
    return channelClosed?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(SyncFailureDto_NoAnswer value)? noAnswer,
    TResult Function(SyncFailureDto_RequestExpired value)? requestExpired,
    TResult Function(SyncFailureDto_Declined value)? declined,
    TResult Function(SyncFailureDto_ChannelClosed value)? channelClosed,
    TResult Function(SyncFailureDto_PublishFailed value)? publishFailed,
    required TResult orElse(),
  }) {
    if (channelClosed != null) {
      return channelClosed(this);
    }
    return orElse();
  }
}

abstract class SyncFailureDto_ChannelClosed extends SyncFailureDto {
  const factory SyncFailureDto_ChannelClosed({required final String detail}) =
      _$SyncFailureDto_ChannelClosedImpl;
  const SyncFailureDto_ChannelClosed._() : super._();

  String get detail;

  /// Create a copy of SyncFailureDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$SyncFailureDto_ChannelClosedImplCopyWith<
          _$SyncFailureDto_ChannelClosedImpl>
      get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$SyncFailureDto_PublishFailedImplCopyWith<$Res> {
  factory _$$SyncFailureDto_PublishFailedImplCopyWith(
          _$SyncFailureDto_PublishFailedImpl value,
          $Res Function(_$SyncFailureDto_PublishFailedImpl) then) =
      __$$SyncFailureDto_PublishFailedImplCopyWithImpl<$Res>;
  @useResult
  $Res call({String detail});
}

/// @nodoc
class __$$SyncFailureDto_PublishFailedImplCopyWithImpl<$Res>
    extends _$SyncFailureDtoCopyWithImpl<$Res,
        _$SyncFailureDto_PublishFailedImpl>
    implements _$$SyncFailureDto_PublishFailedImplCopyWith<$Res> {
  __$$SyncFailureDto_PublishFailedImplCopyWithImpl(
      _$SyncFailureDto_PublishFailedImpl _value,
      $Res Function(_$SyncFailureDto_PublishFailedImpl) _then)
      : super(_value, _then);

  /// Create a copy of SyncFailureDto
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? detail = null,
  }) {
    return _then(_$SyncFailureDto_PublishFailedImpl(
      detail: null == detail
          ? _value.detail
          : detail // ignore: cast_nullable_to_non_nullable
              as String,
    ));
  }
}

/// @nodoc

class _$SyncFailureDto_PublishFailedImpl extends SyncFailureDto_PublishFailed {
  const _$SyncFailureDto_PublishFailedImpl({required this.detail}) : super._();

  @override
  final String detail;

  @override
  String toString() {
    return 'SyncFailureDto.publishFailed(detail: $detail)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$SyncFailureDto_PublishFailedImpl &&
            (identical(other.detail, detail) || other.detail == detail));
  }

  @override
  int get hashCode => Object.hash(runtimeType, detail);

  /// Create a copy of SyncFailureDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$SyncFailureDto_PublishFailedImplCopyWith<
          _$SyncFailureDto_PublishFailedImpl>
      get copyWith => __$$SyncFailureDto_PublishFailedImplCopyWithImpl<
          _$SyncFailureDto_PublishFailedImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() noAnswer,
    required TResult Function() requestExpired,
    required TResult Function() declined,
    required TResult Function(String detail) channelClosed,
    required TResult Function(String detail) publishFailed,
  }) {
    return publishFailed(detail);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function()? noAnswer,
    TResult? Function()? requestExpired,
    TResult? Function()? declined,
    TResult? Function(String detail)? channelClosed,
    TResult? Function(String detail)? publishFailed,
  }) {
    return publishFailed?.call(detail);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? noAnswer,
    TResult Function()? requestExpired,
    TResult Function()? declined,
    TResult Function(String detail)? channelClosed,
    TResult Function(String detail)? publishFailed,
    required TResult orElse(),
  }) {
    if (publishFailed != null) {
      return publishFailed(detail);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(SyncFailureDto_NoAnswer value) noAnswer,
    required TResult Function(SyncFailureDto_RequestExpired value)
        requestExpired,
    required TResult Function(SyncFailureDto_Declined value) declined,
    required TResult Function(SyncFailureDto_ChannelClosed value) channelClosed,
    required TResult Function(SyncFailureDto_PublishFailed value) publishFailed,
  }) {
    return publishFailed(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(SyncFailureDto_NoAnswer value)? noAnswer,
    TResult? Function(SyncFailureDto_RequestExpired value)? requestExpired,
    TResult? Function(SyncFailureDto_Declined value)? declined,
    TResult? Function(SyncFailureDto_ChannelClosed value)? channelClosed,
    TResult? Function(SyncFailureDto_PublishFailed value)? publishFailed,
  }) {
    return publishFailed?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(SyncFailureDto_NoAnswer value)? noAnswer,
    TResult Function(SyncFailureDto_RequestExpired value)? requestExpired,
    TResult Function(SyncFailureDto_Declined value)? declined,
    TResult Function(SyncFailureDto_ChannelClosed value)? channelClosed,
    TResult Function(SyncFailureDto_PublishFailed value)? publishFailed,
    required TResult orElse(),
  }) {
    if (publishFailed != null) {
      return publishFailed(this);
    }
    return orElse();
  }
}

abstract class SyncFailureDto_PublishFailed extends SyncFailureDto {
  const factory SyncFailureDto_PublishFailed({required final String detail}) =
      _$SyncFailureDto_PublishFailedImpl;
  const SyncFailureDto_PublishFailed._() : super._();

  String get detail;

  /// Create a copy of SyncFailureDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$SyncFailureDto_PublishFailedImplCopyWith<
          _$SyncFailureDto_PublishFailedImpl>
      get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
mixin _$SyncProgressDto {
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() starting,
    required TResult Function(BigInt received, BigInt receiveTotal, BigInt sent,
            BigInt sendTotal, double fraction)
        transferring,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function()? starting,
    TResult? Function(BigInt received, BigInt receiveTotal, BigInt sent,
            BigInt sendTotal, double fraction)?
        transferring,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? starting,
    TResult Function(BigInt received, BigInt receiveTotal, BigInt sent,
            BigInt sendTotal, double fraction)?
        transferring,
    required TResult orElse(),
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(SyncProgressDto_Starting value) starting,
    required TResult Function(SyncProgressDto_Transferring value) transferring,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(SyncProgressDto_Starting value)? starting,
    TResult? Function(SyncProgressDto_Transferring value)? transferring,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(SyncProgressDto_Starting value)? starting,
    TResult Function(SyncProgressDto_Transferring value)? transferring,
    required TResult orElse(),
  }) =>
      throw _privateConstructorUsedError;
}

/// @nodoc
abstract class $SyncProgressDtoCopyWith<$Res> {
  factory $SyncProgressDtoCopyWith(
          SyncProgressDto value, $Res Function(SyncProgressDto) then) =
      _$SyncProgressDtoCopyWithImpl<$Res, SyncProgressDto>;
}

/// @nodoc
class _$SyncProgressDtoCopyWithImpl<$Res, $Val extends SyncProgressDto>
    implements $SyncProgressDtoCopyWith<$Res> {
  _$SyncProgressDtoCopyWithImpl(this._value, this._then);

  // ignore: unused_field
  final $Val _value;
  // ignore: unused_field
  final $Res Function($Val) _then;

  /// Create a copy of SyncProgressDto
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc
abstract class _$$SyncProgressDto_StartingImplCopyWith<$Res> {
  factory _$$SyncProgressDto_StartingImplCopyWith(
          _$SyncProgressDto_StartingImpl value,
          $Res Function(_$SyncProgressDto_StartingImpl) then) =
      __$$SyncProgressDto_StartingImplCopyWithImpl<$Res>;
}

/// @nodoc
class __$$SyncProgressDto_StartingImplCopyWithImpl<$Res>
    extends _$SyncProgressDtoCopyWithImpl<$Res, _$SyncProgressDto_StartingImpl>
    implements _$$SyncProgressDto_StartingImplCopyWith<$Res> {
  __$$SyncProgressDto_StartingImplCopyWithImpl(
      _$SyncProgressDto_StartingImpl _value,
      $Res Function(_$SyncProgressDto_StartingImpl) _then)
      : super(_value, _then);

  /// Create a copy of SyncProgressDto
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc

class _$SyncProgressDto_StartingImpl extends SyncProgressDto_Starting {
  const _$SyncProgressDto_StartingImpl() : super._();

  @override
  String toString() {
    return 'SyncProgressDto.starting()';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$SyncProgressDto_StartingImpl);
  }

  @override
  int get hashCode => runtimeType.hashCode;

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() starting,
    required TResult Function(BigInt received, BigInt receiveTotal, BigInt sent,
            BigInt sendTotal, double fraction)
        transferring,
  }) {
    return starting();
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function()? starting,
    TResult? Function(BigInt received, BigInt receiveTotal, BigInt sent,
            BigInt sendTotal, double fraction)?
        transferring,
  }) {
    return starting?.call();
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? starting,
    TResult Function(BigInt received, BigInt receiveTotal, BigInt sent,
            BigInt sendTotal, double fraction)?
        transferring,
    required TResult orElse(),
  }) {
    if (starting != null) {
      return starting();
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(SyncProgressDto_Starting value) starting,
    required TResult Function(SyncProgressDto_Transferring value) transferring,
  }) {
    return starting(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(SyncProgressDto_Starting value)? starting,
    TResult? Function(SyncProgressDto_Transferring value)? transferring,
  }) {
    return starting?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(SyncProgressDto_Starting value)? starting,
    TResult Function(SyncProgressDto_Transferring value)? transferring,
    required TResult orElse(),
  }) {
    if (starting != null) {
      return starting(this);
    }
    return orElse();
  }
}

abstract class SyncProgressDto_Starting extends SyncProgressDto {
  const factory SyncProgressDto_Starting() = _$SyncProgressDto_StartingImpl;
  const SyncProgressDto_Starting._() : super._();
}

/// @nodoc
abstract class _$$SyncProgressDto_TransferringImplCopyWith<$Res> {
  factory _$$SyncProgressDto_TransferringImplCopyWith(
          _$SyncProgressDto_TransferringImpl value,
          $Res Function(_$SyncProgressDto_TransferringImpl) then) =
      __$$SyncProgressDto_TransferringImplCopyWithImpl<$Res>;
  @useResult
  $Res call(
      {BigInt received,
      BigInt receiveTotal,
      BigInt sent,
      BigInt sendTotal,
      double fraction});
}

/// @nodoc
class __$$SyncProgressDto_TransferringImplCopyWithImpl<$Res>
    extends _$SyncProgressDtoCopyWithImpl<$Res,
        _$SyncProgressDto_TransferringImpl>
    implements _$$SyncProgressDto_TransferringImplCopyWith<$Res> {
  __$$SyncProgressDto_TransferringImplCopyWithImpl(
      _$SyncProgressDto_TransferringImpl _value,
      $Res Function(_$SyncProgressDto_TransferringImpl) _then)
      : super(_value, _then);

  /// Create a copy of SyncProgressDto
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? received = null,
    Object? receiveTotal = null,
    Object? sent = null,
    Object? sendTotal = null,
    Object? fraction = null,
  }) {
    return _then(_$SyncProgressDto_TransferringImpl(
      received: null == received
          ? _value.received
          : received // ignore: cast_nullable_to_non_nullable
              as BigInt,
      receiveTotal: null == receiveTotal
          ? _value.receiveTotal
          : receiveTotal // ignore: cast_nullable_to_non_nullable
              as BigInt,
      sent: null == sent
          ? _value.sent
          : sent // ignore: cast_nullable_to_non_nullable
              as BigInt,
      sendTotal: null == sendTotal
          ? _value.sendTotal
          : sendTotal // ignore: cast_nullable_to_non_nullable
              as BigInt,
      fraction: null == fraction
          ? _value.fraction
          : fraction // ignore: cast_nullable_to_non_nullable
              as double,
    ));
  }
}

/// @nodoc

class _$SyncProgressDto_TransferringImpl extends SyncProgressDto_Transferring {
  const _$SyncProgressDto_TransferringImpl(
      {required this.received,
      required this.receiveTotal,
      required this.sent,
      required this.sendTotal,
      required this.fraction})
      : super._();

  @override
  final BigInt received;
  @override
  final BigInt receiveTotal;
  @override
  final BigInt sent;
  @override
  final BigInt sendTotal;
  @override
  final double fraction;

  @override
  String toString() {
    return 'SyncProgressDto.transferring(received: $received, receiveTotal: $receiveTotal, sent: $sent, sendTotal: $sendTotal, fraction: $fraction)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$SyncProgressDto_TransferringImpl &&
            (identical(other.received, received) ||
                other.received == received) &&
            (identical(other.receiveTotal, receiveTotal) ||
                other.receiveTotal == receiveTotal) &&
            (identical(other.sent, sent) || other.sent == sent) &&
            (identical(other.sendTotal, sendTotal) ||
                other.sendTotal == sendTotal) &&
            (identical(other.fraction, fraction) ||
                other.fraction == fraction));
  }

  @override
  int get hashCode => Object.hash(
      runtimeType, received, receiveTotal, sent, sendTotal, fraction);

  /// Create a copy of SyncProgressDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$SyncProgressDto_TransferringImplCopyWith<
          _$SyncProgressDto_TransferringImpl>
      get copyWith => __$$SyncProgressDto_TransferringImplCopyWithImpl<
          _$SyncProgressDto_TransferringImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() starting,
    required TResult Function(BigInt received, BigInt receiveTotal, BigInt sent,
            BigInt sendTotal, double fraction)
        transferring,
  }) {
    return transferring(received, receiveTotal, sent, sendTotal, fraction);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function()? starting,
    TResult? Function(BigInt received, BigInt receiveTotal, BigInt sent,
            BigInt sendTotal, double fraction)?
        transferring,
  }) {
    return transferring?.call(
        received, receiveTotal, sent, sendTotal, fraction);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? starting,
    TResult Function(BigInt received, BigInt receiveTotal, BigInt sent,
            BigInt sendTotal, double fraction)?
        transferring,
    required TResult orElse(),
  }) {
    if (transferring != null) {
      return transferring(received, receiveTotal, sent, sendTotal, fraction);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(SyncProgressDto_Starting value) starting,
    required TResult Function(SyncProgressDto_Transferring value) transferring,
  }) {
    return transferring(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(SyncProgressDto_Starting value)? starting,
    TResult? Function(SyncProgressDto_Transferring value)? transferring,
  }) {
    return transferring?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(SyncProgressDto_Starting value)? starting,
    TResult Function(SyncProgressDto_Transferring value)? transferring,
    required TResult orElse(),
  }) {
    if (transferring != null) {
      return transferring(this);
    }
    return orElse();
  }
}

abstract class SyncProgressDto_Transferring extends SyncProgressDto {
  const factory SyncProgressDto_Transferring(
      {required final BigInt received,
      required final BigInt receiveTotal,
      required final BigInt sent,
      required final BigInt sendTotal,
      required final double fraction}) = _$SyncProgressDto_TransferringImpl;
  const SyncProgressDto_Transferring._() : super._();

  BigInt get received;
  BigInt get receiveTotal;
  BigInt get sent;
  BigInt get sendTotal;
  double get fraction;

  /// Create a copy of SyncProgressDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$SyncProgressDto_TransferringImplCopyWith<
          _$SyncProgressDto_TransferringImpl>
      get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
mixin _$SyncRequestUiStateDto {
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() idle,
    required TResult Function() awaitingPeer,
    required TResult Function(String deviceName) awaitingApproval,
    required TResult Function() active,
    required TResult Function(SyncTallyDto tally, String? deviceName) complete,
    required TResult Function(SyncFailureDto reason) failed,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function()? idle,
    TResult? Function()? awaitingPeer,
    TResult? Function(String deviceName)? awaitingApproval,
    TResult? Function()? active,
    TResult? Function(SyncTallyDto tally, String? deviceName)? complete,
    TResult? Function(SyncFailureDto reason)? failed,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? idle,
    TResult Function()? awaitingPeer,
    TResult Function(String deviceName)? awaitingApproval,
    TResult Function()? active,
    TResult Function(SyncTallyDto tally, String? deviceName)? complete,
    TResult Function(SyncFailureDto reason)? failed,
    required TResult orElse(),
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(SyncRequestUiStateDto_Idle value) idle,
    required TResult Function(SyncRequestUiStateDto_AwaitingPeer value)
        awaitingPeer,
    required TResult Function(SyncRequestUiStateDto_AwaitingApproval value)
        awaitingApproval,
    required TResult Function(SyncRequestUiStateDto_Active value) active,
    required TResult Function(SyncRequestUiStateDto_Complete value) complete,
    required TResult Function(SyncRequestUiStateDto_Failed value) failed,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(SyncRequestUiStateDto_Idle value)? idle,
    TResult? Function(SyncRequestUiStateDto_AwaitingPeer value)? awaitingPeer,
    TResult? Function(SyncRequestUiStateDto_AwaitingApproval value)?
        awaitingApproval,
    TResult? Function(SyncRequestUiStateDto_Active value)? active,
    TResult? Function(SyncRequestUiStateDto_Complete value)? complete,
    TResult? Function(SyncRequestUiStateDto_Failed value)? failed,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(SyncRequestUiStateDto_Idle value)? idle,
    TResult Function(SyncRequestUiStateDto_AwaitingPeer value)? awaitingPeer,
    TResult Function(SyncRequestUiStateDto_AwaitingApproval value)?
        awaitingApproval,
    TResult Function(SyncRequestUiStateDto_Active value)? active,
    TResult Function(SyncRequestUiStateDto_Complete value)? complete,
    TResult Function(SyncRequestUiStateDto_Failed value)? failed,
    required TResult orElse(),
  }) =>
      throw _privateConstructorUsedError;
}

/// @nodoc
abstract class $SyncRequestUiStateDtoCopyWith<$Res> {
  factory $SyncRequestUiStateDtoCopyWith(SyncRequestUiStateDto value,
          $Res Function(SyncRequestUiStateDto) then) =
      _$SyncRequestUiStateDtoCopyWithImpl<$Res, SyncRequestUiStateDto>;
}

/// @nodoc
class _$SyncRequestUiStateDtoCopyWithImpl<$Res,
        $Val extends SyncRequestUiStateDto>
    implements $SyncRequestUiStateDtoCopyWith<$Res> {
  _$SyncRequestUiStateDtoCopyWithImpl(this._value, this._then);

  // ignore: unused_field
  final $Val _value;
  // ignore: unused_field
  final $Res Function($Val) _then;

  /// Create a copy of SyncRequestUiStateDto
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc
abstract class _$$SyncRequestUiStateDto_IdleImplCopyWith<$Res> {
  factory _$$SyncRequestUiStateDto_IdleImplCopyWith(
          _$SyncRequestUiStateDto_IdleImpl value,
          $Res Function(_$SyncRequestUiStateDto_IdleImpl) then) =
      __$$SyncRequestUiStateDto_IdleImplCopyWithImpl<$Res>;
}

/// @nodoc
class __$$SyncRequestUiStateDto_IdleImplCopyWithImpl<$Res>
    extends _$SyncRequestUiStateDtoCopyWithImpl<$Res,
        _$SyncRequestUiStateDto_IdleImpl>
    implements _$$SyncRequestUiStateDto_IdleImplCopyWith<$Res> {
  __$$SyncRequestUiStateDto_IdleImplCopyWithImpl(
      _$SyncRequestUiStateDto_IdleImpl _value,
      $Res Function(_$SyncRequestUiStateDto_IdleImpl) _then)
      : super(_value, _then);

  /// Create a copy of SyncRequestUiStateDto
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc

class _$SyncRequestUiStateDto_IdleImpl extends SyncRequestUiStateDto_Idle {
  const _$SyncRequestUiStateDto_IdleImpl() : super._();

  @override
  String toString() {
    return 'SyncRequestUiStateDto.idle()';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$SyncRequestUiStateDto_IdleImpl);
  }

  @override
  int get hashCode => runtimeType.hashCode;

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() idle,
    required TResult Function() awaitingPeer,
    required TResult Function(String deviceName) awaitingApproval,
    required TResult Function() active,
    required TResult Function(SyncTallyDto tally, String? deviceName) complete,
    required TResult Function(SyncFailureDto reason) failed,
  }) {
    return idle();
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function()? idle,
    TResult? Function()? awaitingPeer,
    TResult? Function(String deviceName)? awaitingApproval,
    TResult? Function()? active,
    TResult? Function(SyncTallyDto tally, String? deviceName)? complete,
    TResult? Function(SyncFailureDto reason)? failed,
  }) {
    return idle?.call();
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? idle,
    TResult Function()? awaitingPeer,
    TResult Function(String deviceName)? awaitingApproval,
    TResult Function()? active,
    TResult Function(SyncTallyDto tally, String? deviceName)? complete,
    TResult Function(SyncFailureDto reason)? failed,
    required TResult orElse(),
  }) {
    if (idle != null) {
      return idle();
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(SyncRequestUiStateDto_Idle value) idle,
    required TResult Function(SyncRequestUiStateDto_AwaitingPeer value)
        awaitingPeer,
    required TResult Function(SyncRequestUiStateDto_AwaitingApproval value)
        awaitingApproval,
    required TResult Function(SyncRequestUiStateDto_Active value) active,
    required TResult Function(SyncRequestUiStateDto_Complete value) complete,
    required TResult Function(SyncRequestUiStateDto_Failed value) failed,
  }) {
    return idle(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(SyncRequestUiStateDto_Idle value)? idle,
    TResult? Function(SyncRequestUiStateDto_AwaitingPeer value)? awaitingPeer,
    TResult? Function(SyncRequestUiStateDto_AwaitingApproval value)?
        awaitingApproval,
    TResult? Function(SyncRequestUiStateDto_Active value)? active,
    TResult? Function(SyncRequestUiStateDto_Complete value)? complete,
    TResult? Function(SyncRequestUiStateDto_Failed value)? failed,
  }) {
    return idle?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(SyncRequestUiStateDto_Idle value)? idle,
    TResult Function(SyncRequestUiStateDto_AwaitingPeer value)? awaitingPeer,
    TResult Function(SyncRequestUiStateDto_AwaitingApproval value)?
        awaitingApproval,
    TResult Function(SyncRequestUiStateDto_Active value)? active,
    TResult Function(SyncRequestUiStateDto_Complete value)? complete,
    TResult Function(SyncRequestUiStateDto_Failed value)? failed,
    required TResult orElse(),
  }) {
    if (idle != null) {
      return idle(this);
    }
    return orElse();
  }
}

abstract class SyncRequestUiStateDto_Idle extends SyncRequestUiStateDto {
  const factory SyncRequestUiStateDto_Idle() = _$SyncRequestUiStateDto_IdleImpl;
  const SyncRequestUiStateDto_Idle._() : super._();
}

/// @nodoc
abstract class _$$SyncRequestUiStateDto_AwaitingPeerImplCopyWith<$Res> {
  factory _$$SyncRequestUiStateDto_AwaitingPeerImplCopyWith(
          _$SyncRequestUiStateDto_AwaitingPeerImpl value,
          $Res Function(_$SyncRequestUiStateDto_AwaitingPeerImpl) then) =
      __$$SyncRequestUiStateDto_AwaitingPeerImplCopyWithImpl<$Res>;
}

/// @nodoc
class __$$SyncRequestUiStateDto_AwaitingPeerImplCopyWithImpl<$Res>
    extends _$SyncRequestUiStateDtoCopyWithImpl<$Res,
        _$SyncRequestUiStateDto_AwaitingPeerImpl>
    implements _$$SyncRequestUiStateDto_AwaitingPeerImplCopyWith<$Res> {
  __$$SyncRequestUiStateDto_AwaitingPeerImplCopyWithImpl(
      _$SyncRequestUiStateDto_AwaitingPeerImpl _value,
      $Res Function(_$SyncRequestUiStateDto_AwaitingPeerImpl) _then)
      : super(_value, _then);

  /// Create a copy of SyncRequestUiStateDto
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc

class _$SyncRequestUiStateDto_AwaitingPeerImpl
    extends SyncRequestUiStateDto_AwaitingPeer {
  const _$SyncRequestUiStateDto_AwaitingPeerImpl() : super._();

  @override
  String toString() {
    return 'SyncRequestUiStateDto.awaitingPeer()';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$SyncRequestUiStateDto_AwaitingPeerImpl);
  }

  @override
  int get hashCode => runtimeType.hashCode;

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() idle,
    required TResult Function() awaitingPeer,
    required TResult Function(String deviceName) awaitingApproval,
    required TResult Function() active,
    required TResult Function(SyncTallyDto tally, String? deviceName) complete,
    required TResult Function(SyncFailureDto reason) failed,
  }) {
    return awaitingPeer();
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function()? idle,
    TResult? Function()? awaitingPeer,
    TResult? Function(String deviceName)? awaitingApproval,
    TResult? Function()? active,
    TResult? Function(SyncTallyDto tally, String? deviceName)? complete,
    TResult? Function(SyncFailureDto reason)? failed,
  }) {
    return awaitingPeer?.call();
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? idle,
    TResult Function()? awaitingPeer,
    TResult Function(String deviceName)? awaitingApproval,
    TResult Function()? active,
    TResult Function(SyncTallyDto tally, String? deviceName)? complete,
    TResult Function(SyncFailureDto reason)? failed,
    required TResult orElse(),
  }) {
    if (awaitingPeer != null) {
      return awaitingPeer();
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(SyncRequestUiStateDto_Idle value) idle,
    required TResult Function(SyncRequestUiStateDto_AwaitingPeer value)
        awaitingPeer,
    required TResult Function(SyncRequestUiStateDto_AwaitingApproval value)
        awaitingApproval,
    required TResult Function(SyncRequestUiStateDto_Active value) active,
    required TResult Function(SyncRequestUiStateDto_Complete value) complete,
    required TResult Function(SyncRequestUiStateDto_Failed value) failed,
  }) {
    return awaitingPeer(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(SyncRequestUiStateDto_Idle value)? idle,
    TResult? Function(SyncRequestUiStateDto_AwaitingPeer value)? awaitingPeer,
    TResult? Function(SyncRequestUiStateDto_AwaitingApproval value)?
        awaitingApproval,
    TResult? Function(SyncRequestUiStateDto_Active value)? active,
    TResult? Function(SyncRequestUiStateDto_Complete value)? complete,
    TResult? Function(SyncRequestUiStateDto_Failed value)? failed,
  }) {
    return awaitingPeer?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(SyncRequestUiStateDto_Idle value)? idle,
    TResult Function(SyncRequestUiStateDto_AwaitingPeer value)? awaitingPeer,
    TResult Function(SyncRequestUiStateDto_AwaitingApproval value)?
        awaitingApproval,
    TResult Function(SyncRequestUiStateDto_Active value)? active,
    TResult Function(SyncRequestUiStateDto_Complete value)? complete,
    TResult Function(SyncRequestUiStateDto_Failed value)? failed,
    required TResult orElse(),
  }) {
    if (awaitingPeer != null) {
      return awaitingPeer(this);
    }
    return orElse();
  }
}

abstract class SyncRequestUiStateDto_AwaitingPeer
    extends SyncRequestUiStateDto {
  const factory SyncRequestUiStateDto_AwaitingPeer() =
      _$SyncRequestUiStateDto_AwaitingPeerImpl;
  const SyncRequestUiStateDto_AwaitingPeer._() : super._();
}

/// @nodoc
abstract class _$$SyncRequestUiStateDto_AwaitingApprovalImplCopyWith<$Res> {
  factory _$$SyncRequestUiStateDto_AwaitingApprovalImplCopyWith(
          _$SyncRequestUiStateDto_AwaitingApprovalImpl value,
          $Res Function(_$SyncRequestUiStateDto_AwaitingApprovalImpl) then) =
      __$$SyncRequestUiStateDto_AwaitingApprovalImplCopyWithImpl<$Res>;
  @useResult
  $Res call({String deviceName});
}

/// @nodoc
class __$$SyncRequestUiStateDto_AwaitingApprovalImplCopyWithImpl<$Res>
    extends _$SyncRequestUiStateDtoCopyWithImpl<$Res,
        _$SyncRequestUiStateDto_AwaitingApprovalImpl>
    implements _$$SyncRequestUiStateDto_AwaitingApprovalImplCopyWith<$Res> {
  __$$SyncRequestUiStateDto_AwaitingApprovalImplCopyWithImpl(
      _$SyncRequestUiStateDto_AwaitingApprovalImpl _value,
      $Res Function(_$SyncRequestUiStateDto_AwaitingApprovalImpl) _then)
      : super(_value, _then);

  /// Create a copy of SyncRequestUiStateDto
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? deviceName = null,
  }) {
    return _then(_$SyncRequestUiStateDto_AwaitingApprovalImpl(
      deviceName: null == deviceName
          ? _value.deviceName
          : deviceName // ignore: cast_nullable_to_non_nullable
              as String,
    ));
  }
}

/// @nodoc

class _$SyncRequestUiStateDto_AwaitingApprovalImpl
    extends SyncRequestUiStateDto_AwaitingApproval {
  const _$SyncRequestUiStateDto_AwaitingApprovalImpl({required this.deviceName})
      : super._();

  @override
  final String deviceName;

  @override
  String toString() {
    return 'SyncRequestUiStateDto.awaitingApproval(deviceName: $deviceName)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$SyncRequestUiStateDto_AwaitingApprovalImpl &&
            (identical(other.deviceName, deviceName) ||
                other.deviceName == deviceName));
  }

  @override
  int get hashCode => Object.hash(runtimeType, deviceName);

  /// Create a copy of SyncRequestUiStateDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$SyncRequestUiStateDto_AwaitingApprovalImplCopyWith<
          _$SyncRequestUiStateDto_AwaitingApprovalImpl>
      get copyWith =>
          __$$SyncRequestUiStateDto_AwaitingApprovalImplCopyWithImpl<
              _$SyncRequestUiStateDto_AwaitingApprovalImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() idle,
    required TResult Function() awaitingPeer,
    required TResult Function(String deviceName) awaitingApproval,
    required TResult Function() active,
    required TResult Function(SyncTallyDto tally, String? deviceName) complete,
    required TResult Function(SyncFailureDto reason) failed,
  }) {
    return awaitingApproval(deviceName);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function()? idle,
    TResult? Function()? awaitingPeer,
    TResult? Function(String deviceName)? awaitingApproval,
    TResult? Function()? active,
    TResult? Function(SyncTallyDto tally, String? deviceName)? complete,
    TResult? Function(SyncFailureDto reason)? failed,
  }) {
    return awaitingApproval?.call(deviceName);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? idle,
    TResult Function()? awaitingPeer,
    TResult Function(String deviceName)? awaitingApproval,
    TResult Function()? active,
    TResult Function(SyncTallyDto tally, String? deviceName)? complete,
    TResult Function(SyncFailureDto reason)? failed,
    required TResult orElse(),
  }) {
    if (awaitingApproval != null) {
      return awaitingApproval(deviceName);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(SyncRequestUiStateDto_Idle value) idle,
    required TResult Function(SyncRequestUiStateDto_AwaitingPeer value)
        awaitingPeer,
    required TResult Function(SyncRequestUiStateDto_AwaitingApproval value)
        awaitingApproval,
    required TResult Function(SyncRequestUiStateDto_Active value) active,
    required TResult Function(SyncRequestUiStateDto_Complete value) complete,
    required TResult Function(SyncRequestUiStateDto_Failed value) failed,
  }) {
    return awaitingApproval(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(SyncRequestUiStateDto_Idle value)? idle,
    TResult? Function(SyncRequestUiStateDto_AwaitingPeer value)? awaitingPeer,
    TResult? Function(SyncRequestUiStateDto_AwaitingApproval value)?
        awaitingApproval,
    TResult? Function(SyncRequestUiStateDto_Active value)? active,
    TResult? Function(SyncRequestUiStateDto_Complete value)? complete,
    TResult? Function(SyncRequestUiStateDto_Failed value)? failed,
  }) {
    return awaitingApproval?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(SyncRequestUiStateDto_Idle value)? idle,
    TResult Function(SyncRequestUiStateDto_AwaitingPeer value)? awaitingPeer,
    TResult Function(SyncRequestUiStateDto_AwaitingApproval value)?
        awaitingApproval,
    TResult Function(SyncRequestUiStateDto_Active value)? active,
    TResult Function(SyncRequestUiStateDto_Complete value)? complete,
    TResult Function(SyncRequestUiStateDto_Failed value)? failed,
    required TResult orElse(),
  }) {
    if (awaitingApproval != null) {
      return awaitingApproval(this);
    }
    return orElse();
  }
}

abstract class SyncRequestUiStateDto_AwaitingApproval
    extends SyncRequestUiStateDto {
  const factory SyncRequestUiStateDto_AwaitingApproval(
          {required final String deviceName}) =
      _$SyncRequestUiStateDto_AwaitingApprovalImpl;
  const SyncRequestUiStateDto_AwaitingApproval._() : super._();

  String get deviceName;

  /// Create a copy of SyncRequestUiStateDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$SyncRequestUiStateDto_AwaitingApprovalImplCopyWith<
          _$SyncRequestUiStateDto_AwaitingApprovalImpl>
      get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$SyncRequestUiStateDto_ActiveImplCopyWith<$Res> {
  factory _$$SyncRequestUiStateDto_ActiveImplCopyWith(
          _$SyncRequestUiStateDto_ActiveImpl value,
          $Res Function(_$SyncRequestUiStateDto_ActiveImpl) then) =
      __$$SyncRequestUiStateDto_ActiveImplCopyWithImpl<$Res>;
}

/// @nodoc
class __$$SyncRequestUiStateDto_ActiveImplCopyWithImpl<$Res>
    extends _$SyncRequestUiStateDtoCopyWithImpl<$Res,
        _$SyncRequestUiStateDto_ActiveImpl>
    implements _$$SyncRequestUiStateDto_ActiveImplCopyWith<$Res> {
  __$$SyncRequestUiStateDto_ActiveImplCopyWithImpl(
      _$SyncRequestUiStateDto_ActiveImpl _value,
      $Res Function(_$SyncRequestUiStateDto_ActiveImpl) _then)
      : super(_value, _then);

  /// Create a copy of SyncRequestUiStateDto
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc

class _$SyncRequestUiStateDto_ActiveImpl extends SyncRequestUiStateDto_Active {
  const _$SyncRequestUiStateDto_ActiveImpl() : super._();

  @override
  String toString() {
    return 'SyncRequestUiStateDto.active()';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$SyncRequestUiStateDto_ActiveImpl);
  }

  @override
  int get hashCode => runtimeType.hashCode;

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() idle,
    required TResult Function() awaitingPeer,
    required TResult Function(String deviceName) awaitingApproval,
    required TResult Function() active,
    required TResult Function(SyncTallyDto tally, String? deviceName) complete,
    required TResult Function(SyncFailureDto reason) failed,
  }) {
    return active();
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function()? idle,
    TResult? Function()? awaitingPeer,
    TResult? Function(String deviceName)? awaitingApproval,
    TResult? Function()? active,
    TResult? Function(SyncTallyDto tally, String? deviceName)? complete,
    TResult? Function(SyncFailureDto reason)? failed,
  }) {
    return active?.call();
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? idle,
    TResult Function()? awaitingPeer,
    TResult Function(String deviceName)? awaitingApproval,
    TResult Function()? active,
    TResult Function(SyncTallyDto tally, String? deviceName)? complete,
    TResult Function(SyncFailureDto reason)? failed,
    required TResult orElse(),
  }) {
    if (active != null) {
      return active();
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(SyncRequestUiStateDto_Idle value) idle,
    required TResult Function(SyncRequestUiStateDto_AwaitingPeer value)
        awaitingPeer,
    required TResult Function(SyncRequestUiStateDto_AwaitingApproval value)
        awaitingApproval,
    required TResult Function(SyncRequestUiStateDto_Active value) active,
    required TResult Function(SyncRequestUiStateDto_Complete value) complete,
    required TResult Function(SyncRequestUiStateDto_Failed value) failed,
  }) {
    return active(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(SyncRequestUiStateDto_Idle value)? idle,
    TResult? Function(SyncRequestUiStateDto_AwaitingPeer value)? awaitingPeer,
    TResult? Function(SyncRequestUiStateDto_AwaitingApproval value)?
        awaitingApproval,
    TResult? Function(SyncRequestUiStateDto_Active value)? active,
    TResult? Function(SyncRequestUiStateDto_Complete value)? complete,
    TResult? Function(SyncRequestUiStateDto_Failed value)? failed,
  }) {
    return active?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(SyncRequestUiStateDto_Idle value)? idle,
    TResult Function(SyncRequestUiStateDto_AwaitingPeer value)? awaitingPeer,
    TResult Function(SyncRequestUiStateDto_AwaitingApproval value)?
        awaitingApproval,
    TResult Function(SyncRequestUiStateDto_Active value)? active,
    TResult Function(SyncRequestUiStateDto_Complete value)? complete,
    TResult Function(SyncRequestUiStateDto_Failed value)? failed,
    required TResult orElse(),
  }) {
    if (active != null) {
      return active(this);
    }
    return orElse();
  }
}

abstract class SyncRequestUiStateDto_Active extends SyncRequestUiStateDto {
  const factory SyncRequestUiStateDto_Active() =
      _$SyncRequestUiStateDto_ActiveImpl;
  const SyncRequestUiStateDto_Active._() : super._();
}

/// @nodoc
abstract class _$$SyncRequestUiStateDto_CompleteImplCopyWith<$Res> {
  factory _$$SyncRequestUiStateDto_CompleteImplCopyWith(
          _$SyncRequestUiStateDto_CompleteImpl value,
          $Res Function(_$SyncRequestUiStateDto_CompleteImpl) then) =
      __$$SyncRequestUiStateDto_CompleteImplCopyWithImpl<$Res>;
  @useResult
  $Res call({SyncTallyDto tally, String? deviceName});
}

/// @nodoc
class __$$SyncRequestUiStateDto_CompleteImplCopyWithImpl<$Res>
    extends _$SyncRequestUiStateDtoCopyWithImpl<$Res,
        _$SyncRequestUiStateDto_CompleteImpl>
    implements _$$SyncRequestUiStateDto_CompleteImplCopyWith<$Res> {
  __$$SyncRequestUiStateDto_CompleteImplCopyWithImpl(
      _$SyncRequestUiStateDto_CompleteImpl _value,
      $Res Function(_$SyncRequestUiStateDto_CompleteImpl) _then)
      : super(_value, _then);

  /// Create a copy of SyncRequestUiStateDto
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? tally = null,
    Object? deviceName = freezed,
  }) {
    return _then(_$SyncRequestUiStateDto_CompleteImpl(
      tally: null == tally
          ? _value.tally
          : tally // ignore: cast_nullable_to_non_nullable
              as SyncTallyDto,
      deviceName: freezed == deviceName
          ? _value.deviceName
          : deviceName // ignore: cast_nullable_to_non_nullable
              as String?,
    ));
  }
}

/// @nodoc

class _$SyncRequestUiStateDto_CompleteImpl
    extends SyncRequestUiStateDto_Complete {
  const _$SyncRequestUiStateDto_CompleteImpl(
      {required this.tally, this.deviceName})
      : super._();

  @override
  final SyncTallyDto tally;
  @override
  final String? deviceName;

  @override
  String toString() {
    return 'SyncRequestUiStateDto.complete(tally: $tally, deviceName: $deviceName)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$SyncRequestUiStateDto_CompleteImpl &&
            (identical(other.tally, tally) || other.tally == tally) &&
            (identical(other.deviceName, deviceName) ||
                other.deviceName == deviceName));
  }

  @override
  int get hashCode => Object.hash(runtimeType, tally, deviceName);

  /// Create a copy of SyncRequestUiStateDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$SyncRequestUiStateDto_CompleteImplCopyWith<
          _$SyncRequestUiStateDto_CompleteImpl>
      get copyWith => __$$SyncRequestUiStateDto_CompleteImplCopyWithImpl<
          _$SyncRequestUiStateDto_CompleteImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() idle,
    required TResult Function() awaitingPeer,
    required TResult Function(String deviceName) awaitingApproval,
    required TResult Function() active,
    required TResult Function(SyncTallyDto tally, String? deviceName) complete,
    required TResult Function(SyncFailureDto reason) failed,
  }) {
    return complete(tally, deviceName);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function()? idle,
    TResult? Function()? awaitingPeer,
    TResult? Function(String deviceName)? awaitingApproval,
    TResult? Function()? active,
    TResult? Function(SyncTallyDto tally, String? deviceName)? complete,
    TResult? Function(SyncFailureDto reason)? failed,
  }) {
    return complete?.call(tally, deviceName);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? idle,
    TResult Function()? awaitingPeer,
    TResult Function(String deviceName)? awaitingApproval,
    TResult Function()? active,
    TResult Function(SyncTallyDto tally, String? deviceName)? complete,
    TResult Function(SyncFailureDto reason)? failed,
    required TResult orElse(),
  }) {
    if (complete != null) {
      return complete(tally, deviceName);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(SyncRequestUiStateDto_Idle value) idle,
    required TResult Function(SyncRequestUiStateDto_AwaitingPeer value)
        awaitingPeer,
    required TResult Function(SyncRequestUiStateDto_AwaitingApproval value)
        awaitingApproval,
    required TResult Function(SyncRequestUiStateDto_Active value) active,
    required TResult Function(SyncRequestUiStateDto_Complete value) complete,
    required TResult Function(SyncRequestUiStateDto_Failed value) failed,
  }) {
    return complete(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(SyncRequestUiStateDto_Idle value)? idle,
    TResult? Function(SyncRequestUiStateDto_AwaitingPeer value)? awaitingPeer,
    TResult? Function(SyncRequestUiStateDto_AwaitingApproval value)?
        awaitingApproval,
    TResult? Function(SyncRequestUiStateDto_Active value)? active,
    TResult? Function(SyncRequestUiStateDto_Complete value)? complete,
    TResult? Function(SyncRequestUiStateDto_Failed value)? failed,
  }) {
    return complete?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(SyncRequestUiStateDto_Idle value)? idle,
    TResult Function(SyncRequestUiStateDto_AwaitingPeer value)? awaitingPeer,
    TResult Function(SyncRequestUiStateDto_AwaitingApproval value)?
        awaitingApproval,
    TResult Function(SyncRequestUiStateDto_Active value)? active,
    TResult Function(SyncRequestUiStateDto_Complete value)? complete,
    TResult Function(SyncRequestUiStateDto_Failed value)? failed,
    required TResult orElse(),
  }) {
    if (complete != null) {
      return complete(this);
    }
    return orElse();
  }
}

abstract class SyncRequestUiStateDto_Complete extends SyncRequestUiStateDto {
  const factory SyncRequestUiStateDto_Complete(
      {required final SyncTallyDto tally,
      final String? deviceName}) = _$SyncRequestUiStateDto_CompleteImpl;
  const SyncRequestUiStateDto_Complete._() : super._();

  SyncTallyDto get tally;
  String? get deviceName;

  /// Create a copy of SyncRequestUiStateDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$SyncRequestUiStateDto_CompleteImplCopyWith<
          _$SyncRequestUiStateDto_CompleteImpl>
      get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$SyncRequestUiStateDto_FailedImplCopyWith<$Res> {
  factory _$$SyncRequestUiStateDto_FailedImplCopyWith(
          _$SyncRequestUiStateDto_FailedImpl value,
          $Res Function(_$SyncRequestUiStateDto_FailedImpl) then) =
      __$$SyncRequestUiStateDto_FailedImplCopyWithImpl<$Res>;
  @useResult
  $Res call({SyncFailureDto reason});

  $SyncFailureDtoCopyWith<$Res> get reason;
}

/// @nodoc
class __$$SyncRequestUiStateDto_FailedImplCopyWithImpl<$Res>
    extends _$SyncRequestUiStateDtoCopyWithImpl<$Res,
        _$SyncRequestUiStateDto_FailedImpl>
    implements _$$SyncRequestUiStateDto_FailedImplCopyWith<$Res> {
  __$$SyncRequestUiStateDto_FailedImplCopyWithImpl(
      _$SyncRequestUiStateDto_FailedImpl _value,
      $Res Function(_$SyncRequestUiStateDto_FailedImpl) _then)
      : super(_value, _then);

  /// Create a copy of SyncRequestUiStateDto
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? reason = null,
  }) {
    return _then(_$SyncRequestUiStateDto_FailedImpl(
      reason: null == reason
          ? _value.reason
          : reason // ignore: cast_nullable_to_non_nullable
              as SyncFailureDto,
    ));
  }

  /// Create a copy of SyncRequestUiStateDto
  /// with the given fields replaced by the non-null parameter values.
  @override
  @pragma('vm:prefer-inline')
  $SyncFailureDtoCopyWith<$Res> get reason {
    return $SyncFailureDtoCopyWith<$Res>(_value.reason, (value) {
      return _then(_value.copyWith(reason: value));
    });
  }
}

/// @nodoc

class _$SyncRequestUiStateDto_FailedImpl extends SyncRequestUiStateDto_Failed {
  const _$SyncRequestUiStateDto_FailedImpl({required this.reason}) : super._();

  @override
  final SyncFailureDto reason;

  @override
  String toString() {
    return 'SyncRequestUiStateDto.failed(reason: $reason)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$SyncRequestUiStateDto_FailedImpl &&
            (identical(other.reason, reason) || other.reason == reason));
  }

  @override
  int get hashCode => Object.hash(runtimeType, reason);

  /// Create a copy of SyncRequestUiStateDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$SyncRequestUiStateDto_FailedImplCopyWith<
          _$SyncRequestUiStateDto_FailedImpl>
      get copyWith => __$$SyncRequestUiStateDto_FailedImplCopyWithImpl<
          _$SyncRequestUiStateDto_FailedImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() idle,
    required TResult Function() awaitingPeer,
    required TResult Function(String deviceName) awaitingApproval,
    required TResult Function() active,
    required TResult Function(SyncTallyDto tally, String? deviceName) complete,
    required TResult Function(SyncFailureDto reason) failed,
  }) {
    return failed(reason);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function()? idle,
    TResult? Function()? awaitingPeer,
    TResult? Function(String deviceName)? awaitingApproval,
    TResult? Function()? active,
    TResult? Function(SyncTallyDto tally, String? deviceName)? complete,
    TResult? Function(SyncFailureDto reason)? failed,
  }) {
    return failed?.call(reason);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? idle,
    TResult Function()? awaitingPeer,
    TResult Function(String deviceName)? awaitingApproval,
    TResult Function()? active,
    TResult Function(SyncTallyDto tally, String? deviceName)? complete,
    TResult Function(SyncFailureDto reason)? failed,
    required TResult orElse(),
  }) {
    if (failed != null) {
      return failed(reason);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(SyncRequestUiStateDto_Idle value) idle,
    required TResult Function(SyncRequestUiStateDto_AwaitingPeer value)
        awaitingPeer,
    required TResult Function(SyncRequestUiStateDto_AwaitingApproval value)
        awaitingApproval,
    required TResult Function(SyncRequestUiStateDto_Active value) active,
    required TResult Function(SyncRequestUiStateDto_Complete value) complete,
    required TResult Function(SyncRequestUiStateDto_Failed value) failed,
  }) {
    return failed(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(SyncRequestUiStateDto_Idle value)? idle,
    TResult? Function(SyncRequestUiStateDto_AwaitingPeer value)? awaitingPeer,
    TResult? Function(SyncRequestUiStateDto_AwaitingApproval value)?
        awaitingApproval,
    TResult? Function(SyncRequestUiStateDto_Active value)? active,
    TResult? Function(SyncRequestUiStateDto_Complete value)? complete,
    TResult? Function(SyncRequestUiStateDto_Failed value)? failed,
  }) {
    return failed?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(SyncRequestUiStateDto_Idle value)? idle,
    TResult Function(SyncRequestUiStateDto_AwaitingPeer value)? awaitingPeer,
    TResult Function(SyncRequestUiStateDto_AwaitingApproval value)?
        awaitingApproval,
    TResult Function(SyncRequestUiStateDto_Active value)? active,
    TResult Function(SyncRequestUiStateDto_Complete value)? complete,
    TResult Function(SyncRequestUiStateDto_Failed value)? failed,
    required TResult orElse(),
  }) {
    if (failed != null) {
      return failed(this);
    }
    return orElse();
  }
}

abstract class SyncRequestUiStateDto_Failed extends SyncRequestUiStateDto {
  const factory SyncRequestUiStateDto_Failed(
          {required final SyncFailureDto reason}) =
      _$SyncRequestUiStateDto_FailedImpl;
  const SyncRequestUiStateDto_Failed._() : super._();

  SyncFailureDto get reason;

  /// Create a copy of SyncRequestUiStateDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$SyncRequestUiStateDto_FailedImplCopyWith<
          _$SyncRequestUiStateDto_FailedImpl>
      get copyWith => throw _privateConstructorUsedError;
}
