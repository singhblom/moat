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
mixin _$ConvInventoryDto {
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(List<String> rkeys) complete,
    required TResult Function(String oldest, String newest, BigInt count) range,
    required TResult Function() empty,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(List<String> rkeys)? complete,
    TResult? Function(String oldest, String newest, BigInt count)? range,
    TResult? Function()? empty,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(List<String> rkeys)? complete,
    TResult Function(String oldest, String newest, BigInt count)? range,
    TResult Function()? empty,
    required TResult orElse(),
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(ConvInventoryDto_Complete value) complete,
    required TResult Function(ConvInventoryDto_Range value) range,
    required TResult Function(ConvInventoryDto_Empty value) empty,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(ConvInventoryDto_Complete value)? complete,
    TResult? Function(ConvInventoryDto_Range value)? range,
    TResult? Function(ConvInventoryDto_Empty value)? empty,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(ConvInventoryDto_Complete value)? complete,
    TResult Function(ConvInventoryDto_Range value)? range,
    TResult Function(ConvInventoryDto_Empty value)? empty,
    required TResult orElse(),
  }) =>
      throw _privateConstructorUsedError;
}

/// @nodoc
abstract class $ConvInventoryDtoCopyWith<$Res> {
  factory $ConvInventoryDtoCopyWith(
          ConvInventoryDto value, $Res Function(ConvInventoryDto) then) =
      _$ConvInventoryDtoCopyWithImpl<$Res, ConvInventoryDto>;
}

/// @nodoc
class _$ConvInventoryDtoCopyWithImpl<$Res, $Val extends ConvInventoryDto>
    implements $ConvInventoryDtoCopyWith<$Res> {
  _$ConvInventoryDtoCopyWithImpl(this._value, this._then);

  // ignore: unused_field
  final $Val _value;
  // ignore: unused_field
  final $Res Function($Val) _then;

  /// Create a copy of ConvInventoryDto
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc
abstract class _$$ConvInventoryDto_CompleteImplCopyWith<$Res> {
  factory _$$ConvInventoryDto_CompleteImplCopyWith(
          _$ConvInventoryDto_CompleteImpl value,
          $Res Function(_$ConvInventoryDto_CompleteImpl) then) =
      __$$ConvInventoryDto_CompleteImplCopyWithImpl<$Res>;
  @useResult
  $Res call({List<String> rkeys});
}

/// @nodoc
class __$$ConvInventoryDto_CompleteImplCopyWithImpl<$Res>
    extends _$ConvInventoryDtoCopyWithImpl<$Res,
        _$ConvInventoryDto_CompleteImpl>
    implements _$$ConvInventoryDto_CompleteImplCopyWith<$Res> {
  __$$ConvInventoryDto_CompleteImplCopyWithImpl(
      _$ConvInventoryDto_CompleteImpl _value,
      $Res Function(_$ConvInventoryDto_CompleteImpl) _then)
      : super(_value, _then);

  /// Create a copy of ConvInventoryDto
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? rkeys = null,
  }) {
    return _then(_$ConvInventoryDto_CompleteImpl(
      rkeys: null == rkeys
          ? _value._rkeys
          : rkeys // ignore: cast_nullable_to_non_nullable
              as List<String>,
    ));
  }
}

/// @nodoc

class _$ConvInventoryDto_CompleteImpl extends ConvInventoryDto_Complete {
  const _$ConvInventoryDto_CompleteImpl({required final List<String> rkeys})
      : _rkeys = rkeys,
        super._();

  final List<String> _rkeys;
  @override
  List<String> get rkeys {
    if (_rkeys is EqualUnmodifiableListView) return _rkeys;
    // ignore: implicit_dynamic_type
    return EqualUnmodifiableListView(_rkeys);
  }

  @override
  String toString() {
    return 'ConvInventoryDto.complete(rkeys: $rkeys)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$ConvInventoryDto_CompleteImpl &&
            const DeepCollectionEquality().equals(other._rkeys, _rkeys));
  }

  @override
  int get hashCode =>
      Object.hash(runtimeType, const DeepCollectionEquality().hash(_rkeys));

  /// Create a copy of ConvInventoryDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$ConvInventoryDto_CompleteImplCopyWith<_$ConvInventoryDto_CompleteImpl>
      get copyWith => __$$ConvInventoryDto_CompleteImplCopyWithImpl<
          _$ConvInventoryDto_CompleteImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(List<String> rkeys) complete,
    required TResult Function(String oldest, String newest, BigInt count) range,
    required TResult Function() empty,
  }) {
    return complete(rkeys);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(List<String> rkeys)? complete,
    TResult? Function(String oldest, String newest, BigInt count)? range,
    TResult? Function()? empty,
  }) {
    return complete?.call(rkeys);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(List<String> rkeys)? complete,
    TResult Function(String oldest, String newest, BigInt count)? range,
    TResult Function()? empty,
    required TResult orElse(),
  }) {
    if (complete != null) {
      return complete(rkeys);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(ConvInventoryDto_Complete value) complete,
    required TResult Function(ConvInventoryDto_Range value) range,
    required TResult Function(ConvInventoryDto_Empty value) empty,
  }) {
    return complete(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(ConvInventoryDto_Complete value)? complete,
    TResult? Function(ConvInventoryDto_Range value)? range,
    TResult? Function(ConvInventoryDto_Empty value)? empty,
  }) {
    return complete?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(ConvInventoryDto_Complete value)? complete,
    TResult Function(ConvInventoryDto_Range value)? range,
    TResult Function(ConvInventoryDto_Empty value)? empty,
    required TResult orElse(),
  }) {
    if (complete != null) {
      return complete(this);
    }
    return orElse();
  }
}

abstract class ConvInventoryDto_Complete extends ConvInventoryDto {
  const factory ConvInventoryDto_Complete({required final List<String> rkeys}) =
      _$ConvInventoryDto_CompleteImpl;
  const ConvInventoryDto_Complete._() : super._();

  List<String> get rkeys;

  /// Create a copy of ConvInventoryDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$ConvInventoryDto_CompleteImplCopyWith<_$ConvInventoryDto_CompleteImpl>
      get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$ConvInventoryDto_RangeImplCopyWith<$Res> {
  factory _$$ConvInventoryDto_RangeImplCopyWith(
          _$ConvInventoryDto_RangeImpl value,
          $Res Function(_$ConvInventoryDto_RangeImpl) then) =
      __$$ConvInventoryDto_RangeImplCopyWithImpl<$Res>;
  @useResult
  $Res call({String oldest, String newest, BigInt count});
}

/// @nodoc
class __$$ConvInventoryDto_RangeImplCopyWithImpl<$Res>
    extends _$ConvInventoryDtoCopyWithImpl<$Res, _$ConvInventoryDto_RangeImpl>
    implements _$$ConvInventoryDto_RangeImplCopyWith<$Res> {
  __$$ConvInventoryDto_RangeImplCopyWithImpl(
      _$ConvInventoryDto_RangeImpl _value,
      $Res Function(_$ConvInventoryDto_RangeImpl) _then)
      : super(_value, _then);

  /// Create a copy of ConvInventoryDto
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? oldest = null,
    Object? newest = null,
    Object? count = null,
  }) {
    return _then(_$ConvInventoryDto_RangeImpl(
      oldest: null == oldest
          ? _value.oldest
          : oldest // ignore: cast_nullable_to_non_nullable
              as String,
      newest: null == newest
          ? _value.newest
          : newest // ignore: cast_nullable_to_non_nullable
              as String,
      count: null == count
          ? _value.count
          : count // ignore: cast_nullable_to_non_nullable
              as BigInt,
    ));
  }
}

/// @nodoc

class _$ConvInventoryDto_RangeImpl extends ConvInventoryDto_Range {
  const _$ConvInventoryDto_RangeImpl(
      {required this.oldest, required this.newest, required this.count})
      : super._();

  @override
  final String oldest;
  @override
  final String newest;
  @override
  final BigInt count;

  @override
  String toString() {
    return 'ConvInventoryDto.range(oldest: $oldest, newest: $newest, count: $count)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$ConvInventoryDto_RangeImpl &&
            (identical(other.oldest, oldest) || other.oldest == oldest) &&
            (identical(other.newest, newest) || other.newest == newest) &&
            (identical(other.count, count) || other.count == count));
  }

  @override
  int get hashCode => Object.hash(runtimeType, oldest, newest, count);

  /// Create a copy of ConvInventoryDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$ConvInventoryDto_RangeImplCopyWith<_$ConvInventoryDto_RangeImpl>
      get copyWith => __$$ConvInventoryDto_RangeImplCopyWithImpl<
          _$ConvInventoryDto_RangeImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(List<String> rkeys) complete,
    required TResult Function(String oldest, String newest, BigInt count) range,
    required TResult Function() empty,
  }) {
    return range(oldest, newest, count);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(List<String> rkeys)? complete,
    TResult? Function(String oldest, String newest, BigInt count)? range,
    TResult? Function()? empty,
  }) {
    return range?.call(oldest, newest, count);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(List<String> rkeys)? complete,
    TResult Function(String oldest, String newest, BigInt count)? range,
    TResult Function()? empty,
    required TResult orElse(),
  }) {
    if (range != null) {
      return range(oldest, newest, count);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(ConvInventoryDto_Complete value) complete,
    required TResult Function(ConvInventoryDto_Range value) range,
    required TResult Function(ConvInventoryDto_Empty value) empty,
  }) {
    return range(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(ConvInventoryDto_Complete value)? complete,
    TResult? Function(ConvInventoryDto_Range value)? range,
    TResult? Function(ConvInventoryDto_Empty value)? empty,
  }) {
    return range?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(ConvInventoryDto_Complete value)? complete,
    TResult Function(ConvInventoryDto_Range value)? range,
    TResult Function(ConvInventoryDto_Empty value)? empty,
    required TResult orElse(),
  }) {
    if (range != null) {
      return range(this);
    }
    return orElse();
  }
}

abstract class ConvInventoryDto_Range extends ConvInventoryDto {
  const factory ConvInventoryDto_Range(
      {required final String oldest,
      required final String newest,
      required final BigInt count}) = _$ConvInventoryDto_RangeImpl;
  const ConvInventoryDto_Range._() : super._();

  String get oldest;
  String get newest;
  BigInt get count;

  /// Create a copy of ConvInventoryDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$ConvInventoryDto_RangeImplCopyWith<_$ConvInventoryDto_RangeImpl>
      get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$ConvInventoryDto_EmptyImplCopyWith<$Res> {
  factory _$$ConvInventoryDto_EmptyImplCopyWith(
          _$ConvInventoryDto_EmptyImpl value,
          $Res Function(_$ConvInventoryDto_EmptyImpl) then) =
      __$$ConvInventoryDto_EmptyImplCopyWithImpl<$Res>;
}

/// @nodoc
class __$$ConvInventoryDto_EmptyImplCopyWithImpl<$Res>
    extends _$ConvInventoryDtoCopyWithImpl<$Res, _$ConvInventoryDto_EmptyImpl>
    implements _$$ConvInventoryDto_EmptyImplCopyWith<$Res> {
  __$$ConvInventoryDto_EmptyImplCopyWithImpl(
      _$ConvInventoryDto_EmptyImpl _value,
      $Res Function(_$ConvInventoryDto_EmptyImpl) _then)
      : super(_value, _then);

  /// Create a copy of ConvInventoryDto
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc

class _$ConvInventoryDto_EmptyImpl extends ConvInventoryDto_Empty {
  const _$ConvInventoryDto_EmptyImpl() : super._();

  @override
  String toString() {
    return 'ConvInventoryDto.empty()';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$ConvInventoryDto_EmptyImpl);
  }

  @override
  int get hashCode => runtimeType.hashCode;

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(List<String> rkeys) complete,
    required TResult Function(String oldest, String newest, BigInt count) range,
    required TResult Function() empty,
  }) {
    return empty();
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(List<String> rkeys)? complete,
    TResult? Function(String oldest, String newest, BigInt count)? range,
    TResult? Function()? empty,
  }) {
    return empty?.call();
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(List<String> rkeys)? complete,
    TResult Function(String oldest, String newest, BigInt count)? range,
    TResult Function()? empty,
    required TResult orElse(),
  }) {
    if (empty != null) {
      return empty();
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(ConvInventoryDto_Complete value) complete,
    required TResult Function(ConvInventoryDto_Range value) range,
    required TResult Function(ConvInventoryDto_Empty value) empty,
  }) {
    return empty(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(ConvInventoryDto_Complete value)? complete,
    TResult? Function(ConvInventoryDto_Range value)? range,
    TResult? Function(ConvInventoryDto_Empty value)? empty,
  }) {
    return empty?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(ConvInventoryDto_Complete value)? complete,
    TResult Function(ConvInventoryDto_Range value)? range,
    TResult Function(ConvInventoryDto_Empty value)? empty,
    required TResult orElse(),
  }) {
    if (empty != null) {
      return empty(this);
    }
    return orElse();
  }
}

abstract class ConvInventoryDto_Empty extends ConvInventoryDto {
  const factory ConvInventoryDto_Empty() = _$ConvInventoryDto_EmptyImpl;
  const ConvInventoryDto_Empty._() : super._();
}

/// @nodoc
mixin _$PairingCommandDto {
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(Uint8List ciphertext) sendFrame,
    required TResult Function(Uint8List deviceId, List<OfferedKpDto> kps)
        seedKpPool,
    required TResult Function(Uint8List tag, Uint8List ciphertext)
        publishRingCommit,
    required TResult Function(String deviceName, String did)
        surfaceApprovalPrompt,
    required TResult Function(Uint8List ringId) persistRing,
    required TResult Function(List<SiblingInfoDto> roster) rosterReceived,
    required TResult Function() startSync,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(Uint8List ciphertext)? sendFrame,
    TResult? Function(Uint8List deviceId, List<OfferedKpDto> kps)? seedKpPool,
    TResult? Function(Uint8List tag, Uint8List ciphertext)? publishRingCommit,
    TResult? Function(String deviceName, String did)? surfaceApprovalPrompt,
    TResult? Function(Uint8List ringId)? persistRing,
    TResult? Function(List<SiblingInfoDto> roster)? rosterReceived,
    TResult? Function()? startSync,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(Uint8List ciphertext)? sendFrame,
    TResult Function(Uint8List deviceId, List<OfferedKpDto> kps)? seedKpPool,
    TResult Function(Uint8List tag, Uint8List ciphertext)? publishRingCommit,
    TResult Function(String deviceName, String did)? surfaceApprovalPrompt,
    TResult Function(Uint8List ringId)? persistRing,
    TResult Function(List<SiblingInfoDto> roster)? rosterReceived,
    TResult Function()? startSync,
    required TResult orElse(),
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(PairingCommandDto_SendFrame value) sendFrame,
    required TResult Function(PairingCommandDto_SeedKpPool value) seedKpPool,
    required TResult Function(PairingCommandDto_PublishRingCommit value)
        publishRingCommit,
    required TResult Function(PairingCommandDto_SurfaceApprovalPrompt value)
        surfaceApprovalPrompt,
    required TResult Function(PairingCommandDto_PersistRing value) persistRing,
    required TResult Function(PairingCommandDto_RosterReceived value)
        rosterReceived,
    required TResult Function(PairingCommandDto_StartSync value) startSync,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(PairingCommandDto_SendFrame value)? sendFrame,
    TResult? Function(PairingCommandDto_SeedKpPool value)? seedKpPool,
    TResult? Function(PairingCommandDto_PublishRingCommit value)?
        publishRingCommit,
    TResult? Function(PairingCommandDto_SurfaceApprovalPrompt value)?
        surfaceApprovalPrompt,
    TResult? Function(PairingCommandDto_PersistRing value)? persistRing,
    TResult? Function(PairingCommandDto_RosterReceived value)? rosterReceived,
    TResult? Function(PairingCommandDto_StartSync value)? startSync,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(PairingCommandDto_SendFrame value)? sendFrame,
    TResult Function(PairingCommandDto_SeedKpPool value)? seedKpPool,
    TResult Function(PairingCommandDto_PublishRingCommit value)?
        publishRingCommit,
    TResult Function(PairingCommandDto_SurfaceApprovalPrompt value)?
        surfaceApprovalPrompt,
    TResult Function(PairingCommandDto_PersistRing value)? persistRing,
    TResult Function(PairingCommandDto_RosterReceived value)? rosterReceived,
    TResult Function(PairingCommandDto_StartSync value)? startSync,
    required TResult orElse(),
  }) =>
      throw _privateConstructorUsedError;
}

/// @nodoc
abstract class $PairingCommandDtoCopyWith<$Res> {
  factory $PairingCommandDtoCopyWith(
          PairingCommandDto value, $Res Function(PairingCommandDto) then) =
      _$PairingCommandDtoCopyWithImpl<$Res, PairingCommandDto>;
}

/// @nodoc
class _$PairingCommandDtoCopyWithImpl<$Res, $Val extends PairingCommandDto>
    implements $PairingCommandDtoCopyWith<$Res> {
  _$PairingCommandDtoCopyWithImpl(this._value, this._then);

  // ignore: unused_field
  final $Val _value;
  // ignore: unused_field
  final $Res Function($Val) _then;

  /// Create a copy of PairingCommandDto
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc
abstract class _$$PairingCommandDto_SendFrameImplCopyWith<$Res> {
  factory _$$PairingCommandDto_SendFrameImplCopyWith(
          _$PairingCommandDto_SendFrameImpl value,
          $Res Function(_$PairingCommandDto_SendFrameImpl) then) =
      __$$PairingCommandDto_SendFrameImplCopyWithImpl<$Res>;
  @useResult
  $Res call({Uint8List ciphertext});
}

/// @nodoc
class __$$PairingCommandDto_SendFrameImplCopyWithImpl<$Res>
    extends _$PairingCommandDtoCopyWithImpl<$Res,
        _$PairingCommandDto_SendFrameImpl>
    implements _$$PairingCommandDto_SendFrameImplCopyWith<$Res> {
  __$$PairingCommandDto_SendFrameImplCopyWithImpl(
      _$PairingCommandDto_SendFrameImpl _value,
      $Res Function(_$PairingCommandDto_SendFrameImpl) _then)
      : super(_value, _then);

  /// Create a copy of PairingCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? ciphertext = null,
  }) {
    return _then(_$PairingCommandDto_SendFrameImpl(
      ciphertext: null == ciphertext
          ? _value.ciphertext
          : ciphertext // ignore: cast_nullable_to_non_nullable
              as Uint8List,
    ));
  }
}

/// @nodoc

class _$PairingCommandDto_SendFrameImpl extends PairingCommandDto_SendFrame {
  const _$PairingCommandDto_SendFrameImpl({required this.ciphertext})
      : super._();

  @override
  final Uint8List ciphertext;

  @override
  String toString() {
    return 'PairingCommandDto.sendFrame(ciphertext: $ciphertext)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$PairingCommandDto_SendFrameImpl &&
            const DeepCollectionEquality()
                .equals(other.ciphertext, ciphertext));
  }

  @override
  int get hashCode =>
      Object.hash(runtimeType, const DeepCollectionEquality().hash(ciphertext));

  /// Create a copy of PairingCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$PairingCommandDto_SendFrameImplCopyWith<_$PairingCommandDto_SendFrameImpl>
      get copyWith => __$$PairingCommandDto_SendFrameImplCopyWithImpl<
          _$PairingCommandDto_SendFrameImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(Uint8List ciphertext) sendFrame,
    required TResult Function(Uint8List deviceId, List<OfferedKpDto> kps)
        seedKpPool,
    required TResult Function(Uint8List tag, Uint8List ciphertext)
        publishRingCommit,
    required TResult Function(String deviceName, String did)
        surfaceApprovalPrompt,
    required TResult Function(Uint8List ringId) persistRing,
    required TResult Function(List<SiblingInfoDto> roster) rosterReceived,
    required TResult Function() startSync,
  }) {
    return sendFrame(ciphertext);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(Uint8List ciphertext)? sendFrame,
    TResult? Function(Uint8List deviceId, List<OfferedKpDto> kps)? seedKpPool,
    TResult? Function(Uint8List tag, Uint8List ciphertext)? publishRingCommit,
    TResult? Function(String deviceName, String did)? surfaceApprovalPrompt,
    TResult? Function(Uint8List ringId)? persistRing,
    TResult? Function(List<SiblingInfoDto> roster)? rosterReceived,
    TResult? Function()? startSync,
  }) {
    return sendFrame?.call(ciphertext);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(Uint8List ciphertext)? sendFrame,
    TResult Function(Uint8List deviceId, List<OfferedKpDto> kps)? seedKpPool,
    TResult Function(Uint8List tag, Uint8List ciphertext)? publishRingCommit,
    TResult Function(String deviceName, String did)? surfaceApprovalPrompt,
    TResult Function(Uint8List ringId)? persistRing,
    TResult Function(List<SiblingInfoDto> roster)? rosterReceived,
    TResult Function()? startSync,
    required TResult orElse(),
  }) {
    if (sendFrame != null) {
      return sendFrame(ciphertext);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(PairingCommandDto_SendFrame value) sendFrame,
    required TResult Function(PairingCommandDto_SeedKpPool value) seedKpPool,
    required TResult Function(PairingCommandDto_PublishRingCommit value)
        publishRingCommit,
    required TResult Function(PairingCommandDto_SurfaceApprovalPrompt value)
        surfaceApprovalPrompt,
    required TResult Function(PairingCommandDto_PersistRing value) persistRing,
    required TResult Function(PairingCommandDto_RosterReceived value)
        rosterReceived,
    required TResult Function(PairingCommandDto_StartSync value) startSync,
  }) {
    return sendFrame(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(PairingCommandDto_SendFrame value)? sendFrame,
    TResult? Function(PairingCommandDto_SeedKpPool value)? seedKpPool,
    TResult? Function(PairingCommandDto_PublishRingCommit value)?
        publishRingCommit,
    TResult? Function(PairingCommandDto_SurfaceApprovalPrompt value)?
        surfaceApprovalPrompt,
    TResult? Function(PairingCommandDto_PersistRing value)? persistRing,
    TResult? Function(PairingCommandDto_RosterReceived value)? rosterReceived,
    TResult? Function(PairingCommandDto_StartSync value)? startSync,
  }) {
    return sendFrame?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(PairingCommandDto_SendFrame value)? sendFrame,
    TResult Function(PairingCommandDto_SeedKpPool value)? seedKpPool,
    TResult Function(PairingCommandDto_PublishRingCommit value)?
        publishRingCommit,
    TResult Function(PairingCommandDto_SurfaceApprovalPrompt value)?
        surfaceApprovalPrompt,
    TResult Function(PairingCommandDto_PersistRing value)? persistRing,
    TResult Function(PairingCommandDto_RosterReceived value)? rosterReceived,
    TResult Function(PairingCommandDto_StartSync value)? startSync,
    required TResult orElse(),
  }) {
    if (sendFrame != null) {
      return sendFrame(this);
    }
    return orElse();
  }
}

abstract class PairingCommandDto_SendFrame extends PairingCommandDto {
  const factory PairingCommandDto_SendFrame(
          {required final Uint8List ciphertext}) =
      _$PairingCommandDto_SendFrameImpl;
  const PairingCommandDto_SendFrame._() : super._();

  Uint8List get ciphertext;

  /// Create a copy of PairingCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$PairingCommandDto_SendFrameImplCopyWith<_$PairingCommandDto_SendFrameImpl>
      get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$PairingCommandDto_SeedKpPoolImplCopyWith<$Res> {
  factory _$$PairingCommandDto_SeedKpPoolImplCopyWith(
          _$PairingCommandDto_SeedKpPoolImpl value,
          $Res Function(_$PairingCommandDto_SeedKpPoolImpl) then) =
      __$$PairingCommandDto_SeedKpPoolImplCopyWithImpl<$Res>;
  @useResult
  $Res call({Uint8List deviceId, List<OfferedKpDto> kps});
}

/// @nodoc
class __$$PairingCommandDto_SeedKpPoolImplCopyWithImpl<$Res>
    extends _$PairingCommandDtoCopyWithImpl<$Res,
        _$PairingCommandDto_SeedKpPoolImpl>
    implements _$$PairingCommandDto_SeedKpPoolImplCopyWith<$Res> {
  __$$PairingCommandDto_SeedKpPoolImplCopyWithImpl(
      _$PairingCommandDto_SeedKpPoolImpl _value,
      $Res Function(_$PairingCommandDto_SeedKpPoolImpl) _then)
      : super(_value, _then);

  /// Create a copy of PairingCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? deviceId = null,
    Object? kps = null,
  }) {
    return _then(_$PairingCommandDto_SeedKpPoolImpl(
      deviceId: null == deviceId
          ? _value.deviceId
          : deviceId // ignore: cast_nullable_to_non_nullable
              as Uint8List,
      kps: null == kps
          ? _value._kps
          : kps // ignore: cast_nullable_to_non_nullable
              as List<OfferedKpDto>,
    ));
  }
}

/// @nodoc

class _$PairingCommandDto_SeedKpPoolImpl extends PairingCommandDto_SeedKpPool {
  const _$PairingCommandDto_SeedKpPoolImpl(
      {required this.deviceId, required final List<OfferedKpDto> kps})
      : _kps = kps,
        super._();

  @override
  final Uint8List deviceId;
  final List<OfferedKpDto> _kps;
  @override
  List<OfferedKpDto> get kps {
    if (_kps is EqualUnmodifiableListView) return _kps;
    // ignore: implicit_dynamic_type
    return EqualUnmodifiableListView(_kps);
  }

  @override
  String toString() {
    return 'PairingCommandDto.seedKpPool(deviceId: $deviceId, kps: $kps)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$PairingCommandDto_SeedKpPoolImpl &&
            const DeepCollectionEquality().equals(other.deviceId, deviceId) &&
            const DeepCollectionEquality().equals(other._kps, _kps));
  }

  @override
  int get hashCode => Object.hash(
      runtimeType,
      const DeepCollectionEquality().hash(deviceId),
      const DeepCollectionEquality().hash(_kps));

  /// Create a copy of PairingCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$PairingCommandDto_SeedKpPoolImplCopyWith<
          _$PairingCommandDto_SeedKpPoolImpl>
      get copyWith => __$$PairingCommandDto_SeedKpPoolImplCopyWithImpl<
          _$PairingCommandDto_SeedKpPoolImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(Uint8List ciphertext) sendFrame,
    required TResult Function(Uint8List deviceId, List<OfferedKpDto> kps)
        seedKpPool,
    required TResult Function(Uint8List tag, Uint8List ciphertext)
        publishRingCommit,
    required TResult Function(String deviceName, String did)
        surfaceApprovalPrompt,
    required TResult Function(Uint8List ringId) persistRing,
    required TResult Function(List<SiblingInfoDto> roster) rosterReceived,
    required TResult Function() startSync,
  }) {
    return seedKpPool(deviceId, kps);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(Uint8List ciphertext)? sendFrame,
    TResult? Function(Uint8List deviceId, List<OfferedKpDto> kps)? seedKpPool,
    TResult? Function(Uint8List tag, Uint8List ciphertext)? publishRingCommit,
    TResult? Function(String deviceName, String did)? surfaceApprovalPrompt,
    TResult? Function(Uint8List ringId)? persistRing,
    TResult? Function(List<SiblingInfoDto> roster)? rosterReceived,
    TResult? Function()? startSync,
  }) {
    return seedKpPool?.call(deviceId, kps);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(Uint8List ciphertext)? sendFrame,
    TResult Function(Uint8List deviceId, List<OfferedKpDto> kps)? seedKpPool,
    TResult Function(Uint8List tag, Uint8List ciphertext)? publishRingCommit,
    TResult Function(String deviceName, String did)? surfaceApprovalPrompt,
    TResult Function(Uint8List ringId)? persistRing,
    TResult Function(List<SiblingInfoDto> roster)? rosterReceived,
    TResult Function()? startSync,
    required TResult orElse(),
  }) {
    if (seedKpPool != null) {
      return seedKpPool(deviceId, kps);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(PairingCommandDto_SendFrame value) sendFrame,
    required TResult Function(PairingCommandDto_SeedKpPool value) seedKpPool,
    required TResult Function(PairingCommandDto_PublishRingCommit value)
        publishRingCommit,
    required TResult Function(PairingCommandDto_SurfaceApprovalPrompt value)
        surfaceApprovalPrompt,
    required TResult Function(PairingCommandDto_PersistRing value) persistRing,
    required TResult Function(PairingCommandDto_RosterReceived value)
        rosterReceived,
    required TResult Function(PairingCommandDto_StartSync value) startSync,
  }) {
    return seedKpPool(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(PairingCommandDto_SendFrame value)? sendFrame,
    TResult? Function(PairingCommandDto_SeedKpPool value)? seedKpPool,
    TResult? Function(PairingCommandDto_PublishRingCommit value)?
        publishRingCommit,
    TResult? Function(PairingCommandDto_SurfaceApprovalPrompt value)?
        surfaceApprovalPrompt,
    TResult? Function(PairingCommandDto_PersistRing value)? persistRing,
    TResult? Function(PairingCommandDto_RosterReceived value)? rosterReceived,
    TResult? Function(PairingCommandDto_StartSync value)? startSync,
  }) {
    return seedKpPool?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(PairingCommandDto_SendFrame value)? sendFrame,
    TResult Function(PairingCommandDto_SeedKpPool value)? seedKpPool,
    TResult Function(PairingCommandDto_PublishRingCommit value)?
        publishRingCommit,
    TResult Function(PairingCommandDto_SurfaceApprovalPrompt value)?
        surfaceApprovalPrompt,
    TResult Function(PairingCommandDto_PersistRing value)? persistRing,
    TResult Function(PairingCommandDto_RosterReceived value)? rosterReceived,
    TResult Function(PairingCommandDto_StartSync value)? startSync,
    required TResult orElse(),
  }) {
    if (seedKpPool != null) {
      return seedKpPool(this);
    }
    return orElse();
  }
}

abstract class PairingCommandDto_SeedKpPool extends PairingCommandDto {
  const factory PairingCommandDto_SeedKpPool(
          {required final Uint8List deviceId,
          required final List<OfferedKpDto> kps}) =
      _$PairingCommandDto_SeedKpPoolImpl;
  const PairingCommandDto_SeedKpPool._() : super._();

  Uint8List get deviceId;
  List<OfferedKpDto> get kps;

  /// Create a copy of PairingCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$PairingCommandDto_SeedKpPoolImplCopyWith<
          _$PairingCommandDto_SeedKpPoolImpl>
      get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$PairingCommandDto_PublishRingCommitImplCopyWith<$Res> {
  factory _$$PairingCommandDto_PublishRingCommitImplCopyWith(
          _$PairingCommandDto_PublishRingCommitImpl value,
          $Res Function(_$PairingCommandDto_PublishRingCommitImpl) then) =
      __$$PairingCommandDto_PublishRingCommitImplCopyWithImpl<$Res>;
  @useResult
  $Res call({Uint8List tag, Uint8List ciphertext});
}

/// @nodoc
class __$$PairingCommandDto_PublishRingCommitImplCopyWithImpl<$Res>
    extends _$PairingCommandDtoCopyWithImpl<$Res,
        _$PairingCommandDto_PublishRingCommitImpl>
    implements _$$PairingCommandDto_PublishRingCommitImplCopyWith<$Res> {
  __$$PairingCommandDto_PublishRingCommitImplCopyWithImpl(
      _$PairingCommandDto_PublishRingCommitImpl _value,
      $Res Function(_$PairingCommandDto_PublishRingCommitImpl) _then)
      : super(_value, _then);

  /// Create a copy of PairingCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? tag = null,
    Object? ciphertext = null,
  }) {
    return _then(_$PairingCommandDto_PublishRingCommitImpl(
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

class _$PairingCommandDto_PublishRingCommitImpl
    extends PairingCommandDto_PublishRingCommit {
  const _$PairingCommandDto_PublishRingCommitImpl(
      {required this.tag, required this.ciphertext})
      : super._();

  @override
  final Uint8List tag;
  @override
  final Uint8List ciphertext;

  @override
  String toString() {
    return 'PairingCommandDto.publishRingCommit(tag: $tag, ciphertext: $ciphertext)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$PairingCommandDto_PublishRingCommitImpl &&
            const DeepCollectionEquality().equals(other.tag, tag) &&
            const DeepCollectionEquality()
                .equals(other.ciphertext, ciphertext));
  }

  @override
  int get hashCode => Object.hash(
      runtimeType,
      const DeepCollectionEquality().hash(tag),
      const DeepCollectionEquality().hash(ciphertext));

  /// Create a copy of PairingCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$PairingCommandDto_PublishRingCommitImplCopyWith<
          _$PairingCommandDto_PublishRingCommitImpl>
      get copyWith => __$$PairingCommandDto_PublishRingCommitImplCopyWithImpl<
          _$PairingCommandDto_PublishRingCommitImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(Uint8List ciphertext) sendFrame,
    required TResult Function(Uint8List deviceId, List<OfferedKpDto> kps)
        seedKpPool,
    required TResult Function(Uint8List tag, Uint8List ciphertext)
        publishRingCommit,
    required TResult Function(String deviceName, String did)
        surfaceApprovalPrompt,
    required TResult Function(Uint8List ringId) persistRing,
    required TResult Function(List<SiblingInfoDto> roster) rosterReceived,
    required TResult Function() startSync,
  }) {
    return publishRingCommit(tag, ciphertext);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(Uint8List ciphertext)? sendFrame,
    TResult? Function(Uint8List deviceId, List<OfferedKpDto> kps)? seedKpPool,
    TResult? Function(Uint8List tag, Uint8List ciphertext)? publishRingCommit,
    TResult? Function(String deviceName, String did)? surfaceApprovalPrompt,
    TResult? Function(Uint8List ringId)? persistRing,
    TResult? Function(List<SiblingInfoDto> roster)? rosterReceived,
    TResult? Function()? startSync,
  }) {
    return publishRingCommit?.call(tag, ciphertext);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(Uint8List ciphertext)? sendFrame,
    TResult Function(Uint8List deviceId, List<OfferedKpDto> kps)? seedKpPool,
    TResult Function(Uint8List tag, Uint8List ciphertext)? publishRingCommit,
    TResult Function(String deviceName, String did)? surfaceApprovalPrompt,
    TResult Function(Uint8List ringId)? persistRing,
    TResult Function(List<SiblingInfoDto> roster)? rosterReceived,
    TResult Function()? startSync,
    required TResult orElse(),
  }) {
    if (publishRingCommit != null) {
      return publishRingCommit(tag, ciphertext);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(PairingCommandDto_SendFrame value) sendFrame,
    required TResult Function(PairingCommandDto_SeedKpPool value) seedKpPool,
    required TResult Function(PairingCommandDto_PublishRingCommit value)
        publishRingCommit,
    required TResult Function(PairingCommandDto_SurfaceApprovalPrompt value)
        surfaceApprovalPrompt,
    required TResult Function(PairingCommandDto_PersistRing value) persistRing,
    required TResult Function(PairingCommandDto_RosterReceived value)
        rosterReceived,
    required TResult Function(PairingCommandDto_StartSync value) startSync,
  }) {
    return publishRingCommit(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(PairingCommandDto_SendFrame value)? sendFrame,
    TResult? Function(PairingCommandDto_SeedKpPool value)? seedKpPool,
    TResult? Function(PairingCommandDto_PublishRingCommit value)?
        publishRingCommit,
    TResult? Function(PairingCommandDto_SurfaceApprovalPrompt value)?
        surfaceApprovalPrompt,
    TResult? Function(PairingCommandDto_PersistRing value)? persistRing,
    TResult? Function(PairingCommandDto_RosterReceived value)? rosterReceived,
    TResult? Function(PairingCommandDto_StartSync value)? startSync,
  }) {
    return publishRingCommit?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(PairingCommandDto_SendFrame value)? sendFrame,
    TResult Function(PairingCommandDto_SeedKpPool value)? seedKpPool,
    TResult Function(PairingCommandDto_PublishRingCommit value)?
        publishRingCommit,
    TResult Function(PairingCommandDto_SurfaceApprovalPrompt value)?
        surfaceApprovalPrompt,
    TResult Function(PairingCommandDto_PersistRing value)? persistRing,
    TResult Function(PairingCommandDto_RosterReceived value)? rosterReceived,
    TResult Function(PairingCommandDto_StartSync value)? startSync,
    required TResult orElse(),
  }) {
    if (publishRingCommit != null) {
      return publishRingCommit(this);
    }
    return orElse();
  }
}

abstract class PairingCommandDto_PublishRingCommit extends PairingCommandDto {
  const factory PairingCommandDto_PublishRingCommit(
          {required final Uint8List tag, required final Uint8List ciphertext}) =
      _$PairingCommandDto_PublishRingCommitImpl;
  const PairingCommandDto_PublishRingCommit._() : super._();

  Uint8List get tag;
  Uint8List get ciphertext;

  /// Create a copy of PairingCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$PairingCommandDto_PublishRingCommitImplCopyWith<
          _$PairingCommandDto_PublishRingCommitImpl>
      get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$PairingCommandDto_SurfaceApprovalPromptImplCopyWith<$Res> {
  factory _$$PairingCommandDto_SurfaceApprovalPromptImplCopyWith(
          _$PairingCommandDto_SurfaceApprovalPromptImpl value,
          $Res Function(_$PairingCommandDto_SurfaceApprovalPromptImpl) then) =
      __$$PairingCommandDto_SurfaceApprovalPromptImplCopyWithImpl<$Res>;
  @useResult
  $Res call({String deviceName, String did});
}

/// @nodoc
class __$$PairingCommandDto_SurfaceApprovalPromptImplCopyWithImpl<$Res>
    extends _$PairingCommandDtoCopyWithImpl<$Res,
        _$PairingCommandDto_SurfaceApprovalPromptImpl>
    implements _$$PairingCommandDto_SurfaceApprovalPromptImplCopyWith<$Res> {
  __$$PairingCommandDto_SurfaceApprovalPromptImplCopyWithImpl(
      _$PairingCommandDto_SurfaceApprovalPromptImpl _value,
      $Res Function(_$PairingCommandDto_SurfaceApprovalPromptImpl) _then)
      : super(_value, _then);

  /// Create a copy of PairingCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? deviceName = null,
    Object? did = null,
  }) {
    return _then(_$PairingCommandDto_SurfaceApprovalPromptImpl(
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

class _$PairingCommandDto_SurfaceApprovalPromptImpl
    extends PairingCommandDto_SurfaceApprovalPrompt {
  const _$PairingCommandDto_SurfaceApprovalPromptImpl(
      {required this.deviceName, required this.did})
      : super._();

  @override
  final String deviceName;
  @override
  final String did;

  @override
  String toString() {
    return 'PairingCommandDto.surfaceApprovalPrompt(deviceName: $deviceName, did: $did)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$PairingCommandDto_SurfaceApprovalPromptImpl &&
            (identical(other.deviceName, deviceName) ||
                other.deviceName == deviceName) &&
            (identical(other.did, did) || other.did == did));
  }

  @override
  int get hashCode => Object.hash(runtimeType, deviceName, did);

  /// Create a copy of PairingCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$PairingCommandDto_SurfaceApprovalPromptImplCopyWith<
          _$PairingCommandDto_SurfaceApprovalPromptImpl>
      get copyWith =>
          __$$PairingCommandDto_SurfaceApprovalPromptImplCopyWithImpl<
              _$PairingCommandDto_SurfaceApprovalPromptImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(Uint8List ciphertext) sendFrame,
    required TResult Function(Uint8List deviceId, List<OfferedKpDto> kps)
        seedKpPool,
    required TResult Function(Uint8List tag, Uint8List ciphertext)
        publishRingCommit,
    required TResult Function(String deviceName, String did)
        surfaceApprovalPrompt,
    required TResult Function(Uint8List ringId) persistRing,
    required TResult Function(List<SiblingInfoDto> roster) rosterReceived,
    required TResult Function() startSync,
  }) {
    return surfaceApprovalPrompt(deviceName, did);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(Uint8List ciphertext)? sendFrame,
    TResult? Function(Uint8List deviceId, List<OfferedKpDto> kps)? seedKpPool,
    TResult? Function(Uint8List tag, Uint8List ciphertext)? publishRingCommit,
    TResult? Function(String deviceName, String did)? surfaceApprovalPrompt,
    TResult? Function(Uint8List ringId)? persistRing,
    TResult? Function(List<SiblingInfoDto> roster)? rosterReceived,
    TResult? Function()? startSync,
  }) {
    return surfaceApprovalPrompt?.call(deviceName, did);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(Uint8List ciphertext)? sendFrame,
    TResult Function(Uint8List deviceId, List<OfferedKpDto> kps)? seedKpPool,
    TResult Function(Uint8List tag, Uint8List ciphertext)? publishRingCommit,
    TResult Function(String deviceName, String did)? surfaceApprovalPrompt,
    TResult Function(Uint8List ringId)? persistRing,
    TResult Function(List<SiblingInfoDto> roster)? rosterReceived,
    TResult Function()? startSync,
    required TResult orElse(),
  }) {
    if (surfaceApprovalPrompt != null) {
      return surfaceApprovalPrompt(deviceName, did);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(PairingCommandDto_SendFrame value) sendFrame,
    required TResult Function(PairingCommandDto_SeedKpPool value) seedKpPool,
    required TResult Function(PairingCommandDto_PublishRingCommit value)
        publishRingCommit,
    required TResult Function(PairingCommandDto_SurfaceApprovalPrompt value)
        surfaceApprovalPrompt,
    required TResult Function(PairingCommandDto_PersistRing value) persistRing,
    required TResult Function(PairingCommandDto_RosterReceived value)
        rosterReceived,
    required TResult Function(PairingCommandDto_StartSync value) startSync,
  }) {
    return surfaceApprovalPrompt(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(PairingCommandDto_SendFrame value)? sendFrame,
    TResult? Function(PairingCommandDto_SeedKpPool value)? seedKpPool,
    TResult? Function(PairingCommandDto_PublishRingCommit value)?
        publishRingCommit,
    TResult? Function(PairingCommandDto_SurfaceApprovalPrompt value)?
        surfaceApprovalPrompt,
    TResult? Function(PairingCommandDto_PersistRing value)? persistRing,
    TResult? Function(PairingCommandDto_RosterReceived value)? rosterReceived,
    TResult? Function(PairingCommandDto_StartSync value)? startSync,
  }) {
    return surfaceApprovalPrompt?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(PairingCommandDto_SendFrame value)? sendFrame,
    TResult Function(PairingCommandDto_SeedKpPool value)? seedKpPool,
    TResult Function(PairingCommandDto_PublishRingCommit value)?
        publishRingCommit,
    TResult Function(PairingCommandDto_SurfaceApprovalPrompt value)?
        surfaceApprovalPrompt,
    TResult Function(PairingCommandDto_PersistRing value)? persistRing,
    TResult Function(PairingCommandDto_RosterReceived value)? rosterReceived,
    TResult Function(PairingCommandDto_StartSync value)? startSync,
    required TResult orElse(),
  }) {
    if (surfaceApprovalPrompt != null) {
      return surfaceApprovalPrompt(this);
    }
    return orElse();
  }
}

abstract class PairingCommandDto_SurfaceApprovalPrompt
    extends PairingCommandDto {
  const factory PairingCommandDto_SurfaceApprovalPrompt(
          {required final String deviceName, required final String did}) =
      _$PairingCommandDto_SurfaceApprovalPromptImpl;
  const PairingCommandDto_SurfaceApprovalPrompt._() : super._();

  String get deviceName;
  String get did;

  /// Create a copy of PairingCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$PairingCommandDto_SurfaceApprovalPromptImplCopyWith<
          _$PairingCommandDto_SurfaceApprovalPromptImpl>
      get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$PairingCommandDto_PersistRingImplCopyWith<$Res> {
  factory _$$PairingCommandDto_PersistRingImplCopyWith(
          _$PairingCommandDto_PersistRingImpl value,
          $Res Function(_$PairingCommandDto_PersistRingImpl) then) =
      __$$PairingCommandDto_PersistRingImplCopyWithImpl<$Res>;
  @useResult
  $Res call({Uint8List ringId});
}

/// @nodoc
class __$$PairingCommandDto_PersistRingImplCopyWithImpl<$Res>
    extends _$PairingCommandDtoCopyWithImpl<$Res,
        _$PairingCommandDto_PersistRingImpl>
    implements _$$PairingCommandDto_PersistRingImplCopyWith<$Res> {
  __$$PairingCommandDto_PersistRingImplCopyWithImpl(
      _$PairingCommandDto_PersistRingImpl _value,
      $Res Function(_$PairingCommandDto_PersistRingImpl) _then)
      : super(_value, _then);

  /// Create a copy of PairingCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? ringId = null,
  }) {
    return _then(_$PairingCommandDto_PersistRingImpl(
      ringId: null == ringId
          ? _value.ringId
          : ringId // ignore: cast_nullable_to_non_nullable
              as Uint8List,
    ));
  }
}

/// @nodoc

class _$PairingCommandDto_PersistRingImpl
    extends PairingCommandDto_PersistRing {
  const _$PairingCommandDto_PersistRingImpl({required this.ringId}) : super._();

  @override
  final Uint8List ringId;

  @override
  String toString() {
    return 'PairingCommandDto.persistRing(ringId: $ringId)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$PairingCommandDto_PersistRingImpl &&
            const DeepCollectionEquality().equals(other.ringId, ringId));
  }

  @override
  int get hashCode =>
      Object.hash(runtimeType, const DeepCollectionEquality().hash(ringId));

  /// Create a copy of PairingCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$PairingCommandDto_PersistRingImplCopyWith<
          _$PairingCommandDto_PersistRingImpl>
      get copyWith => __$$PairingCommandDto_PersistRingImplCopyWithImpl<
          _$PairingCommandDto_PersistRingImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(Uint8List ciphertext) sendFrame,
    required TResult Function(Uint8List deviceId, List<OfferedKpDto> kps)
        seedKpPool,
    required TResult Function(Uint8List tag, Uint8List ciphertext)
        publishRingCommit,
    required TResult Function(String deviceName, String did)
        surfaceApprovalPrompt,
    required TResult Function(Uint8List ringId) persistRing,
    required TResult Function(List<SiblingInfoDto> roster) rosterReceived,
    required TResult Function() startSync,
  }) {
    return persistRing(ringId);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(Uint8List ciphertext)? sendFrame,
    TResult? Function(Uint8List deviceId, List<OfferedKpDto> kps)? seedKpPool,
    TResult? Function(Uint8List tag, Uint8List ciphertext)? publishRingCommit,
    TResult? Function(String deviceName, String did)? surfaceApprovalPrompt,
    TResult? Function(Uint8List ringId)? persistRing,
    TResult? Function(List<SiblingInfoDto> roster)? rosterReceived,
    TResult? Function()? startSync,
  }) {
    return persistRing?.call(ringId);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(Uint8List ciphertext)? sendFrame,
    TResult Function(Uint8List deviceId, List<OfferedKpDto> kps)? seedKpPool,
    TResult Function(Uint8List tag, Uint8List ciphertext)? publishRingCommit,
    TResult Function(String deviceName, String did)? surfaceApprovalPrompt,
    TResult Function(Uint8List ringId)? persistRing,
    TResult Function(List<SiblingInfoDto> roster)? rosterReceived,
    TResult Function()? startSync,
    required TResult orElse(),
  }) {
    if (persistRing != null) {
      return persistRing(ringId);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(PairingCommandDto_SendFrame value) sendFrame,
    required TResult Function(PairingCommandDto_SeedKpPool value) seedKpPool,
    required TResult Function(PairingCommandDto_PublishRingCommit value)
        publishRingCommit,
    required TResult Function(PairingCommandDto_SurfaceApprovalPrompt value)
        surfaceApprovalPrompt,
    required TResult Function(PairingCommandDto_PersistRing value) persistRing,
    required TResult Function(PairingCommandDto_RosterReceived value)
        rosterReceived,
    required TResult Function(PairingCommandDto_StartSync value) startSync,
  }) {
    return persistRing(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(PairingCommandDto_SendFrame value)? sendFrame,
    TResult? Function(PairingCommandDto_SeedKpPool value)? seedKpPool,
    TResult? Function(PairingCommandDto_PublishRingCommit value)?
        publishRingCommit,
    TResult? Function(PairingCommandDto_SurfaceApprovalPrompt value)?
        surfaceApprovalPrompt,
    TResult? Function(PairingCommandDto_PersistRing value)? persistRing,
    TResult? Function(PairingCommandDto_RosterReceived value)? rosterReceived,
    TResult? Function(PairingCommandDto_StartSync value)? startSync,
  }) {
    return persistRing?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(PairingCommandDto_SendFrame value)? sendFrame,
    TResult Function(PairingCommandDto_SeedKpPool value)? seedKpPool,
    TResult Function(PairingCommandDto_PublishRingCommit value)?
        publishRingCommit,
    TResult Function(PairingCommandDto_SurfaceApprovalPrompt value)?
        surfaceApprovalPrompt,
    TResult Function(PairingCommandDto_PersistRing value)? persistRing,
    TResult Function(PairingCommandDto_RosterReceived value)? rosterReceived,
    TResult Function(PairingCommandDto_StartSync value)? startSync,
    required TResult orElse(),
  }) {
    if (persistRing != null) {
      return persistRing(this);
    }
    return orElse();
  }
}

abstract class PairingCommandDto_PersistRing extends PairingCommandDto {
  const factory PairingCommandDto_PersistRing(
      {required final Uint8List ringId}) = _$PairingCommandDto_PersistRingImpl;
  const PairingCommandDto_PersistRing._() : super._();

  Uint8List get ringId;

  /// Create a copy of PairingCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$PairingCommandDto_PersistRingImplCopyWith<
          _$PairingCommandDto_PersistRingImpl>
      get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$PairingCommandDto_RosterReceivedImplCopyWith<$Res> {
  factory _$$PairingCommandDto_RosterReceivedImplCopyWith(
          _$PairingCommandDto_RosterReceivedImpl value,
          $Res Function(_$PairingCommandDto_RosterReceivedImpl) then) =
      __$$PairingCommandDto_RosterReceivedImplCopyWithImpl<$Res>;
  @useResult
  $Res call({List<SiblingInfoDto> roster});
}

/// @nodoc
class __$$PairingCommandDto_RosterReceivedImplCopyWithImpl<$Res>
    extends _$PairingCommandDtoCopyWithImpl<$Res,
        _$PairingCommandDto_RosterReceivedImpl>
    implements _$$PairingCommandDto_RosterReceivedImplCopyWith<$Res> {
  __$$PairingCommandDto_RosterReceivedImplCopyWithImpl(
      _$PairingCommandDto_RosterReceivedImpl _value,
      $Res Function(_$PairingCommandDto_RosterReceivedImpl) _then)
      : super(_value, _then);

  /// Create a copy of PairingCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? roster = null,
  }) {
    return _then(_$PairingCommandDto_RosterReceivedImpl(
      roster: null == roster
          ? _value._roster
          : roster // ignore: cast_nullable_to_non_nullable
              as List<SiblingInfoDto>,
    ));
  }
}

/// @nodoc

class _$PairingCommandDto_RosterReceivedImpl
    extends PairingCommandDto_RosterReceived {
  const _$PairingCommandDto_RosterReceivedImpl(
      {required final List<SiblingInfoDto> roster})
      : _roster = roster,
        super._();

  final List<SiblingInfoDto> _roster;
  @override
  List<SiblingInfoDto> get roster {
    if (_roster is EqualUnmodifiableListView) return _roster;
    // ignore: implicit_dynamic_type
    return EqualUnmodifiableListView(_roster);
  }

  @override
  String toString() {
    return 'PairingCommandDto.rosterReceived(roster: $roster)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$PairingCommandDto_RosterReceivedImpl &&
            const DeepCollectionEquality().equals(other._roster, _roster));
  }

  @override
  int get hashCode =>
      Object.hash(runtimeType, const DeepCollectionEquality().hash(_roster));

  /// Create a copy of PairingCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$PairingCommandDto_RosterReceivedImplCopyWith<
          _$PairingCommandDto_RosterReceivedImpl>
      get copyWith => __$$PairingCommandDto_RosterReceivedImplCopyWithImpl<
          _$PairingCommandDto_RosterReceivedImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(Uint8List ciphertext) sendFrame,
    required TResult Function(Uint8List deviceId, List<OfferedKpDto> kps)
        seedKpPool,
    required TResult Function(Uint8List tag, Uint8List ciphertext)
        publishRingCommit,
    required TResult Function(String deviceName, String did)
        surfaceApprovalPrompt,
    required TResult Function(Uint8List ringId) persistRing,
    required TResult Function(List<SiblingInfoDto> roster) rosterReceived,
    required TResult Function() startSync,
  }) {
    return rosterReceived(roster);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(Uint8List ciphertext)? sendFrame,
    TResult? Function(Uint8List deviceId, List<OfferedKpDto> kps)? seedKpPool,
    TResult? Function(Uint8List tag, Uint8List ciphertext)? publishRingCommit,
    TResult? Function(String deviceName, String did)? surfaceApprovalPrompt,
    TResult? Function(Uint8List ringId)? persistRing,
    TResult? Function(List<SiblingInfoDto> roster)? rosterReceived,
    TResult? Function()? startSync,
  }) {
    return rosterReceived?.call(roster);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(Uint8List ciphertext)? sendFrame,
    TResult Function(Uint8List deviceId, List<OfferedKpDto> kps)? seedKpPool,
    TResult Function(Uint8List tag, Uint8List ciphertext)? publishRingCommit,
    TResult Function(String deviceName, String did)? surfaceApprovalPrompt,
    TResult Function(Uint8List ringId)? persistRing,
    TResult Function(List<SiblingInfoDto> roster)? rosterReceived,
    TResult Function()? startSync,
    required TResult orElse(),
  }) {
    if (rosterReceived != null) {
      return rosterReceived(roster);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(PairingCommandDto_SendFrame value) sendFrame,
    required TResult Function(PairingCommandDto_SeedKpPool value) seedKpPool,
    required TResult Function(PairingCommandDto_PublishRingCommit value)
        publishRingCommit,
    required TResult Function(PairingCommandDto_SurfaceApprovalPrompt value)
        surfaceApprovalPrompt,
    required TResult Function(PairingCommandDto_PersistRing value) persistRing,
    required TResult Function(PairingCommandDto_RosterReceived value)
        rosterReceived,
    required TResult Function(PairingCommandDto_StartSync value) startSync,
  }) {
    return rosterReceived(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(PairingCommandDto_SendFrame value)? sendFrame,
    TResult? Function(PairingCommandDto_SeedKpPool value)? seedKpPool,
    TResult? Function(PairingCommandDto_PublishRingCommit value)?
        publishRingCommit,
    TResult? Function(PairingCommandDto_SurfaceApprovalPrompt value)?
        surfaceApprovalPrompt,
    TResult? Function(PairingCommandDto_PersistRing value)? persistRing,
    TResult? Function(PairingCommandDto_RosterReceived value)? rosterReceived,
    TResult? Function(PairingCommandDto_StartSync value)? startSync,
  }) {
    return rosterReceived?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(PairingCommandDto_SendFrame value)? sendFrame,
    TResult Function(PairingCommandDto_SeedKpPool value)? seedKpPool,
    TResult Function(PairingCommandDto_PublishRingCommit value)?
        publishRingCommit,
    TResult Function(PairingCommandDto_SurfaceApprovalPrompt value)?
        surfaceApprovalPrompt,
    TResult Function(PairingCommandDto_PersistRing value)? persistRing,
    TResult Function(PairingCommandDto_RosterReceived value)? rosterReceived,
    TResult Function(PairingCommandDto_StartSync value)? startSync,
    required TResult orElse(),
  }) {
    if (rosterReceived != null) {
      return rosterReceived(this);
    }
    return orElse();
  }
}

abstract class PairingCommandDto_RosterReceived extends PairingCommandDto {
  const factory PairingCommandDto_RosterReceived(
          {required final List<SiblingInfoDto> roster}) =
      _$PairingCommandDto_RosterReceivedImpl;
  const PairingCommandDto_RosterReceived._() : super._();

  List<SiblingInfoDto> get roster;

  /// Create a copy of PairingCommandDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$PairingCommandDto_RosterReceivedImplCopyWith<
          _$PairingCommandDto_RosterReceivedImpl>
      get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$PairingCommandDto_StartSyncImplCopyWith<$Res> {
  factory _$$PairingCommandDto_StartSyncImplCopyWith(
          _$PairingCommandDto_StartSyncImpl value,
          $Res Function(_$PairingCommandDto_StartSyncImpl) then) =
      __$$PairingCommandDto_StartSyncImplCopyWithImpl<$Res>;
}

/// @nodoc
class __$$PairingCommandDto_StartSyncImplCopyWithImpl<$Res>
    extends _$PairingCommandDtoCopyWithImpl<$Res,
        _$PairingCommandDto_StartSyncImpl>
    implements _$$PairingCommandDto_StartSyncImplCopyWith<$Res> {
  __$$PairingCommandDto_StartSyncImplCopyWithImpl(
      _$PairingCommandDto_StartSyncImpl _value,
      $Res Function(_$PairingCommandDto_StartSyncImpl) _then)
      : super(_value, _then);

  /// Create a copy of PairingCommandDto
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc

class _$PairingCommandDto_StartSyncImpl extends PairingCommandDto_StartSync {
  const _$PairingCommandDto_StartSyncImpl() : super._();

  @override
  String toString() {
    return 'PairingCommandDto.startSync()';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$PairingCommandDto_StartSyncImpl);
  }

  @override
  int get hashCode => runtimeType.hashCode;

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(Uint8List ciphertext) sendFrame,
    required TResult Function(Uint8List deviceId, List<OfferedKpDto> kps)
        seedKpPool,
    required TResult Function(Uint8List tag, Uint8List ciphertext)
        publishRingCommit,
    required TResult Function(String deviceName, String did)
        surfaceApprovalPrompt,
    required TResult Function(Uint8List ringId) persistRing,
    required TResult Function(List<SiblingInfoDto> roster) rosterReceived,
    required TResult Function() startSync,
  }) {
    return startSync();
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(Uint8List ciphertext)? sendFrame,
    TResult? Function(Uint8List deviceId, List<OfferedKpDto> kps)? seedKpPool,
    TResult? Function(Uint8List tag, Uint8List ciphertext)? publishRingCommit,
    TResult? Function(String deviceName, String did)? surfaceApprovalPrompt,
    TResult? Function(Uint8List ringId)? persistRing,
    TResult? Function(List<SiblingInfoDto> roster)? rosterReceived,
    TResult? Function()? startSync,
  }) {
    return startSync?.call();
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(Uint8List ciphertext)? sendFrame,
    TResult Function(Uint8List deviceId, List<OfferedKpDto> kps)? seedKpPool,
    TResult Function(Uint8List tag, Uint8List ciphertext)? publishRingCommit,
    TResult Function(String deviceName, String did)? surfaceApprovalPrompt,
    TResult Function(Uint8List ringId)? persistRing,
    TResult Function(List<SiblingInfoDto> roster)? rosterReceived,
    TResult Function()? startSync,
    required TResult orElse(),
  }) {
    if (startSync != null) {
      return startSync();
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(PairingCommandDto_SendFrame value) sendFrame,
    required TResult Function(PairingCommandDto_SeedKpPool value) seedKpPool,
    required TResult Function(PairingCommandDto_PublishRingCommit value)
        publishRingCommit,
    required TResult Function(PairingCommandDto_SurfaceApprovalPrompt value)
        surfaceApprovalPrompt,
    required TResult Function(PairingCommandDto_PersistRing value) persistRing,
    required TResult Function(PairingCommandDto_RosterReceived value)
        rosterReceived,
    required TResult Function(PairingCommandDto_StartSync value) startSync,
  }) {
    return startSync(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(PairingCommandDto_SendFrame value)? sendFrame,
    TResult? Function(PairingCommandDto_SeedKpPool value)? seedKpPool,
    TResult? Function(PairingCommandDto_PublishRingCommit value)?
        publishRingCommit,
    TResult? Function(PairingCommandDto_SurfaceApprovalPrompt value)?
        surfaceApprovalPrompt,
    TResult? Function(PairingCommandDto_PersistRing value)? persistRing,
    TResult? Function(PairingCommandDto_RosterReceived value)? rosterReceived,
    TResult? Function(PairingCommandDto_StartSync value)? startSync,
  }) {
    return startSync?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(PairingCommandDto_SendFrame value)? sendFrame,
    TResult Function(PairingCommandDto_SeedKpPool value)? seedKpPool,
    TResult Function(PairingCommandDto_PublishRingCommit value)?
        publishRingCommit,
    TResult Function(PairingCommandDto_SurfaceApprovalPrompt value)?
        surfaceApprovalPrompt,
    TResult Function(PairingCommandDto_PersistRing value)? persistRing,
    TResult Function(PairingCommandDto_RosterReceived value)? rosterReceived,
    TResult Function(PairingCommandDto_StartSync value)? startSync,
    required TResult orElse(),
  }) {
    if (startSync != null) {
      return startSync(this);
    }
    return orElse();
  }
}

abstract class PairingCommandDto_StartSync extends PairingCommandDto {
  const factory PairingCommandDto_StartSync() =
      _$PairingCommandDto_StartSyncImpl;
  const PairingCommandDto_StartSync._() : super._();
}

/// @nodoc
mixin _$PairingUiStateDto {
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() idle,
    required TResult Function(String code, String uri) showingCode,
    required TResult Function() awaitingPeer,
    required TResult Function(String deviceName, String did) awaitingApproval,
    required TResult Function(Uint8List ringId) done,
    required TResult Function(String reason) failed,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function()? idle,
    TResult? Function(String code, String uri)? showingCode,
    TResult? Function()? awaitingPeer,
    TResult? Function(String deviceName, String did)? awaitingApproval,
    TResult? Function(Uint8List ringId)? done,
    TResult? Function(String reason)? failed,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? idle,
    TResult Function(String code, String uri)? showingCode,
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
    required TResult Function(String code, String uri) showingCode,
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
    TResult? Function(String code, String uri)? showingCode,
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
    TResult Function(String code, String uri)? showingCode,
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
  $Res call({String code, String uri});
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
    Object? uri = null,
  }) {
    return _then(_$PairingUiStateDto_ShowingCodeImpl(
      code: null == code
          ? _value.code
          : code // ignore: cast_nullable_to_non_nullable
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
      {required this.code, required this.uri})
      : super._();

  @override
  final String code;
  @override
  final String uri;

  @override
  String toString() {
    return 'PairingUiStateDto.showingCode(code: $code, uri: $uri)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$PairingUiStateDto_ShowingCodeImpl &&
            (identical(other.code, code) || other.code == code) &&
            (identical(other.uri, uri) || other.uri == uri));
  }

  @override
  int get hashCode => Object.hash(runtimeType, code, uri);

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
    required TResult Function(String code, String uri) showingCode,
    required TResult Function() awaitingPeer,
    required TResult Function(String deviceName, String did) awaitingApproval,
    required TResult Function(Uint8List ringId) done,
    required TResult Function(String reason) failed,
  }) {
    return showingCode(code, uri);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function()? idle,
    TResult? Function(String code, String uri)? showingCode,
    TResult? Function()? awaitingPeer,
    TResult? Function(String deviceName, String did)? awaitingApproval,
    TResult? Function(Uint8List ringId)? done,
    TResult? Function(String reason)? failed,
  }) {
    return showingCode?.call(code, uri);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? idle,
    TResult Function(String code, String uri)? showingCode,
    TResult Function()? awaitingPeer,
    TResult Function(String deviceName, String did)? awaitingApproval,
    TResult Function(Uint8List ringId)? done,
    TResult Function(String reason)? failed,
    required TResult orElse(),
  }) {
    if (showingCode != null) {
      return showingCode(code, uri);
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
      required final String uri}) = _$PairingUiStateDto_ShowingCodeImpl;
  const PairingUiStateDto_ShowingCode._() : super._();

  String get code;
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
    required TResult Function(String code, String uri) showingCode,
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
    TResult? Function(String code, String uri)? showingCode,
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
    TResult Function(String code, String uri)? showingCode,
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
    required TResult Function(String code, String uri) showingCode,
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
    TResult? Function(String code, String uri)? showingCode,
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
    TResult Function(String code, String uri)? showingCode,
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
    required TResult Function(String code, String uri) showingCode,
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
    TResult? Function(String code, String uri)? showingCode,
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
    TResult Function(String code, String uri)? showingCode,
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
    required TResult Function(String code, String uri) showingCode,
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
    TResult? Function(String code, String uri)? showingCode,
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
    TResult Function(String code, String uri)? showingCode,
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
mixin _$RingMsgDto {
  Uint8List get token => throw _privateConstructorUsedError;
  Uint8List? get targetDeviceId => throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(Uint8List token, Uint8List? targetDeviceId)
        syncRequest,
    required TResult Function(Uint8List token, Uint8List targetDeviceId)
        syncOffer,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(Uint8List token, Uint8List? targetDeviceId)? syncRequest,
    TResult? Function(Uint8List token, Uint8List targetDeviceId)? syncOffer,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(Uint8List token, Uint8List? targetDeviceId)? syncRequest,
    TResult Function(Uint8List token, Uint8List targetDeviceId)? syncOffer,
    required TResult orElse(),
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(RingMsgDto_SyncRequest value) syncRequest,
    required TResult Function(RingMsgDto_SyncOffer value) syncOffer,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(RingMsgDto_SyncRequest value)? syncRequest,
    TResult? Function(RingMsgDto_SyncOffer value)? syncOffer,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(RingMsgDto_SyncRequest value)? syncRequest,
    TResult Function(RingMsgDto_SyncOffer value)? syncOffer,
    required TResult orElse(),
  }) =>
      throw _privateConstructorUsedError;

  /// Create a copy of RingMsgDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  $RingMsgDtoCopyWith<RingMsgDto> get copyWith =>
      throw _privateConstructorUsedError;
}

/// @nodoc
abstract class $RingMsgDtoCopyWith<$Res> {
  factory $RingMsgDtoCopyWith(
          RingMsgDto value, $Res Function(RingMsgDto) then) =
      _$RingMsgDtoCopyWithImpl<$Res, RingMsgDto>;
  @useResult
  $Res call({Uint8List token, Uint8List targetDeviceId});
}

/// @nodoc
class _$RingMsgDtoCopyWithImpl<$Res, $Val extends RingMsgDto>
    implements $RingMsgDtoCopyWith<$Res> {
  _$RingMsgDtoCopyWithImpl(this._value, this._then);

  // ignore: unused_field
  final $Val _value;
  // ignore: unused_field
  final $Res Function($Val) _then;

  /// Create a copy of RingMsgDto
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? token = null,
    Object? targetDeviceId = null,
  }) {
    return _then(_value.copyWith(
      token: null == token
          ? _value.token
          : token // ignore: cast_nullable_to_non_nullable
              as Uint8List,
      targetDeviceId: null == targetDeviceId
          ? _value.targetDeviceId!
          : targetDeviceId // ignore: cast_nullable_to_non_nullable
              as Uint8List,
    ) as $Val);
  }
}

/// @nodoc
abstract class _$$RingMsgDto_SyncRequestImplCopyWith<$Res>
    implements $RingMsgDtoCopyWith<$Res> {
  factory _$$RingMsgDto_SyncRequestImplCopyWith(
          _$RingMsgDto_SyncRequestImpl value,
          $Res Function(_$RingMsgDto_SyncRequestImpl) then) =
      __$$RingMsgDto_SyncRequestImplCopyWithImpl<$Res>;
  @override
  @useResult
  $Res call({Uint8List token, Uint8List? targetDeviceId});
}

/// @nodoc
class __$$RingMsgDto_SyncRequestImplCopyWithImpl<$Res>
    extends _$RingMsgDtoCopyWithImpl<$Res, _$RingMsgDto_SyncRequestImpl>
    implements _$$RingMsgDto_SyncRequestImplCopyWith<$Res> {
  __$$RingMsgDto_SyncRequestImplCopyWithImpl(
      _$RingMsgDto_SyncRequestImpl _value,
      $Res Function(_$RingMsgDto_SyncRequestImpl) _then)
      : super(_value, _then);

  /// Create a copy of RingMsgDto
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? token = null,
    Object? targetDeviceId = freezed,
  }) {
    return _then(_$RingMsgDto_SyncRequestImpl(
      token: null == token
          ? _value.token
          : token // ignore: cast_nullable_to_non_nullable
              as Uint8List,
      targetDeviceId: freezed == targetDeviceId
          ? _value.targetDeviceId
          : targetDeviceId // ignore: cast_nullable_to_non_nullable
              as Uint8List?,
    ));
  }
}

/// @nodoc

class _$RingMsgDto_SyncRequestImpl extends RingMsgDto_SyncRequest {
  const _$RingMsgDto_SyncRequestImpl({required this.token, this.targetDeviceId})
      : super._();

  @override
  final Uint8List token;
  @override
  final Uint8List? targetDeviceId;

  @override
  String toString() {
    return 'RingMsgDto.syncRequest(token: $token, targetDeviceId: $targetDeviceId)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$RingMsgDto_SyncRequestImpl &&
            const DeepCollectionEquality().equals(other.token, token) &&
            const DeepCollectionEquality()
                .equals(other.targetDeviceId, targetDeviceId));
  }

  @override
  int get hashCode => Object.hash(
      runtimeType,
      const DeepCollectionEquality().hash(token),
      const DeepCollectionEquality().hash(targetDeviceId));

  /// Create a copy of RingMsgDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$RingMsgDto_SyncRequestImplCopyWith<_$RingMsgDto_SyncRequestImpl>
      get copyWith => __$$RingMsgDto_SyncRequestImplCopyWithImpl<
          _$RingMsgDto_SyncRequestImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(Uint8List token, Uint8List? targetDeviceId)
        syncRequest,
    required TResult Function(Uint8List token, Uint8List targetDeviceId)
        syncOffer,
  }) {
    return syncRequest(token, targetDeviceId);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(Uint8List token, Uint8List? targetDeviceId)? syncRequest,
    TResult? Function(Uint8List token, Uint8List targetDeviceId)? syncOffer,
  }) {
    return syncRequest?.call(token, targetDeviceId);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(Uint8List token, Uint8List? targetDeviceId)? syncRequest,
    TResult Function(Uint8List token, Uint8List targetDeviceId)? syncOffer,
    required TResult orElse(),
  }) {
    if (syncRequest != null) {
      return syncRequest(token, targetDeviceId);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(RingMsgDto_SyncRequest value) syncRequest,
    required TResult Function(RingMsgDto_SyncOffer value) syncOffer,
  }) {
    return syncRequest(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(RingMsgDto_SyncRequest value)? syncRequest,
    TResult? Function(RingMsgDto_SyncOffer value)? syncOffer,
  }) {
    return syncRequest?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(RingMsgDto_SyncRequest value)? syncRequest,
    TResult Function(RingMsgDto_SyncOffer value)? syncOffer,
    required TResult orElse(),
  }) {
    if (syncRequest != null) {
      return syncRequest(this);
    }
    return orElse();
  }
}

abstract class RingMsgDto_SyncRequest extends RingMsgDto {
  const factory RingMsgDto_SyncRequest(
      {required final Uint8List token,
      final Uint8List? targetDeviceId}) = _$RingMsgDto_SyncRequestImpl;
  const RingMsgDto_SyncRequest._() : super._();

  @override
  Uint8List get token;
  @override
  Uint8List? get targetDeviceId;

  /// Create a copy of RingMsgDto
  /// with the given fields replaced by the non-null parameter values.
  @override
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$RingMsgDto_SyncRequestImplCopyWith<_$RingMsgDto_SyncRequestImpl>
      get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$RingMsgDto_SyncOfferImplCopyWith<$Res>
    implements $RingMsgDtoCopyWith<$Res> {
  factory _$$RingMsgDto_SyncOfferImplCopyWith(_$RingMsgDto_SyncOfferImpl value,
          $Res Function(_$RingMsgDto_SyncOfferImpl) then) =
      __$$RingMsgDto_SyncOfferImplCopyWithImpl<$Res>;
  @override
  @useResult
  $Res call({Uint8List token, Uint8List targetDeviceId});
}

/// @nodoc
class __$$RingMsgDto_SyncOfferImplCopyWithImpl<$Res>
    extends _$RingMsgDtoCopyWithImpl<$Res, _$RingMsgDto_SyncOfferImpl>
    implements _$$RingMsgDto_SyncOfferImplCopyWith<$Res> {
  __$$RingMsgDto_SyncOfferImplCopyWithImpl(_$RingMsgDto_SyncOfferImpl _value,
      $Res Function(_$RingMsgDto_SyncOfferImpl) _then)
      : super(_value, _then);

  /// Create a copy of RingMsgDto
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? token = null,
    Object? targetDeviceId = null,
  }) {
    return _then(_$RingMsgDto_SyncOfferImpl(
      token: null == token
          ? _value.token
          : token // ignore: cast_nullable_to_non_nullable
              as Uint8List,
      targetDeviceId: null == targetDeviceId
          ? _value.targetDeviceId
          : targetDeviceId // ignore: cast_nullable_to_non_nullable
              as Uint8List,
    ));
  }
}

/// @nodoc

class _$RingMsgDto_SyncOfferImpl extends RingMsgDto_SyncOffer {
  const _$RingMsgDto_SyncOfferImpl(
      {required this.token, required this.targetDeviceId})
      : super._();

  @override
  final Uint8List token;
  @override
  final Uint8List targetDeviceId;

  @override
  String toString() {
    return 'RingMsgDto.syncOffer(token: $token, targetDeviceId: $targetDeviceId)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$RingMsgDto_SyncOfferImpl &&
            const DeepCollectionEquality().equals(other.token, token) &&
            const DeepCollectionEquality()
                .equals(other.targetDeviceId, targetDeviceId));
  }

  @override
  int get hashCode => Object.hash(
      runtimeType,
      const DeepCollectionEquality().hash(token),
      const DeepCollectionEquality().hash(targetDeviceId));

  /// Create a copy of RingMsgDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$RingMsgDto_SyncOfferImplCopyWith<_$RingMsgDto_SyncOfferImpl>
      get copyWith =>
          __$$RingMsgDto_SyncOfferImplCopyWithImpl<_$RingMsgDto_SyncOfferImpl>(
              this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(Uint8List token, Uint8List? targetDeviceId)
        syncRequest,
    required TResult Function(Uint8List token, Uint8List targetDeviceId)
        syncOffer,
  }) {
    return syncOffer(token, targetDeviceId);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(Uint8List token, Uint8List? targetDeviceId)? syncRequest,
    TResult? Function(Uint8List token, Uint8List targetDeviceId)? syncOffer,
  }) {
    return syncOffer?.call(token, targetDeviceId);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(Uint8List token, Uint8List? targetDeviceId)? syncRequest,
    TResult Function(Uint8List token, Uint8List targetDeviceId)? syncOffer,
    required TResult orElse(),
  }) {
    if (syncOffer != null) {
      return syncOffer(token, targetDeviceId);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(RingMsgDto_SyncRequest value) syncRequest,
    required TResult Function(RingMsgDto_SyncOffer value) syncOffer,
  }) {
    return syncOffer(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(RingMsgDto_SyncRequest value)? syncRequest,
    TResult? Function(RingMsgDto_SyncOffer value)? syncOffer,
  }) {
    return syncOffer?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(RingMsgDto_SyncRequest value)? syncRequest,
    TResult Function(RingMsgDto_SyncOffer value)? syncOffer,
    required TResult orElse(),
  }) {
    if (syncOffer != null) {
      return syncOffer(this);
    }
    return orElse();
  }
}

abstract class RingMsgDto_SyncOffer extends RingMsgDto {
  const factory RingMsgDto_SyncOffer(
      {required final Uint8List token,
      required final Uint8List targetDeviceId}) = _$RingMsgDto_SyncOfferImpl;
  const RingMsgDto_SyncOffer._() : super._();

  @override
  Uint8List get token;
  @override
  Uint8List get targetDeviceId;

  /// Create a copy of RingMsgDto
  /// with the given fields replaced by the non-null parameter values.
  @override
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$RingMsgDto_SyncOfferImplCopyWith<_$RingMsgDto_SyncOfferImpl>
      get copyWith => throw _privateConstructorUsedError;
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
mixin _$SyncOutputDto {
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(Uint8List bytes) send,
    required TResult Function(String convId, List<SyncMessageDto> messages)
        store,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(Uint8List bytes)? send,
    TResult? Function(String convId, List<SyncMessageDto> messages)? store,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(Uint8List bytes)? send,
    TResult Function(String convId, List<SyncMessageDto> messages)? store,
    required TResult orElse(),
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(SyncOutputDto_Send value) send,
    required TResult Function(SyncOutputDto_Store value) store,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(SyncOutputDto_Send value)? send,
    TResult? Function(SyncOutputDto_Store value)? store,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(SyncOutputDto_Send value)? send,
    TResult Function(SyncOutputDto_Store value)? store,
    required TResult orElse(),
  }) =>
      throw _privateConstructorUsedError;
}

/// @nodoc
abstract class $SyncOutputDtoCopyWith<$Res> {
  factory $SyncOutputDtoCopyWith(
          SyncOutputDto value, $Res Function(SyncOutputDto) then) =
      _$SyncOutputDtoCopyWithImpl<$Res, SyncOutputDto>;
}

/// @nodoc
class _$SyncOutputDtoCopyWithImpl<$Res, $Val extends SyncOutputDto>
    implements $SyncOutputDtoCopyWith<$Res> {
  _$SyncOutputDtoCopyWithImpl(this._value, this._then);

  // ignore: unused_field
  final $Val _value;
  // ignore: unused_field
  final $Res Function($Val) _then;

  /// Create a copy of SyncOutputDto
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc
abstract class _$$SyncOutputDto_SendImplCopyWith<$Res> {
  factory _$$SyncOutputDto_SendImplCopyWith(_$SyncOutputDto_SendImpl value,
          $Res Function(_$SyncOutputDto_SendImpl) then) =
      __$$SyncOutputDto_SendImplCopyWithImpl<$Res>;
  @useResult
  $Res call({Uint8List bytes});
}

/// @nodoc
class __$$SyncOutputDto_SendImplCopyWithImpl<$Res>
    extends _$SyncOutputDtoCopyWithImpl<$Res, _$SyncOutputDto_SendImpl>
    implements _$$SyncOutputDto_SendImplCopyWith<$Res> {
  __$$SyncOutputDto_SendImplCopyWithImpl(_$SyncOutputDto_SendImpl _value,
      $Res Function(_$SyncOutputDto_SendImpl) _then)
      : super(_value, _then);

  /// Create a copy of SyncOutputDto
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? bytes = null,
  }) {
    return _then(_$SyncOutputDto_SendImpl(
      bytes: null == bytes
          ? _value.bytes
          : bytes // ignore: cast_nullable_to_non_nullable
              as Uint8List,
    ));
  }
}

/// @nodoc

class _$SyncOutputDto_SendImpl extends SyncOutputDto_Send {
  const _$SyncOutputDto_SendImpl({required this.bytes}) : super._();

  @override
  final Uint8List bytes;

  @override
  String toString() {
    return 'SyncOutputDto.send(bytes: $bytes)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$SyncOutputDto_SendImpl &&
            const DeepCollectionEquality().equals(other.bytes, bytes));
  }

  @override
  int get hashCode =>
      Object.hash(runtimeType, const DeepCollectionEquality().hash(bytes));

  /// Create a copy of SyncOutputDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$SyncOutputDto_SendImplCopyWith<_$SyncOutputDto_SendImpl> get copyWith =>
      __$$SyncOutputDto_SendImplCopyWithImpl<_$SyncOutputDto_SendImpl>(
          this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(Uint8List bytes) send,
    required TResult Function(String convId, List<SyncMessageDto> messages)
        store,
  }) {
    return send(bytes);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(Uint8List bytes)? send,
    TResult? Function(String convId, List<SyncMessageDto> messages)? store,
  }) {
    return send?.call(bytes);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(Uint8List bytes)? send,
    TResult Function(String convId, List<SyncMessageDto> messages)? store,
    required TResult orElse(),
  }) {
    if (send != null) {
      return send(bytes);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(SyncOutputDto_Send value) send,
    required TResult Function(SyncOutputDto_Store value) store,
  }) {
    return send(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(SyncOutputDto_Send value)? send,
    TResult? Function(SyncOutputDto_Store value)? store,
  }) {
    return send?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(SyncOutputDto_Send value)? send,
    TResult Function(SyncOutputDto_Store value)? store,
    required TResult orElse(),
  }) {
    if (send != null) {
      return send(this);
    }
    return orElse();
  }
}

abstract class SyncOutputDto_Send extends SyncOutputDto {
  const factory SyncOutputDto_Send({required final Uint8List bytes}) =
      _$SyncOutputDto_SendImpl;
  const SyncOutputDto_Send._() : super._();

  Uint8List get bytes;

  /// Create a copy of SyncOutputDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$SyncOutputDto_SendImplCopyWith<_$SyncOutputDto_SendImpl> get copyWith =>
      throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$SyncOutputDto_StoreImplCopyWith<$Res> {
  factory _$$SyncOutputDto_StoreImplCopyWith(_$SyncOutputDto_StoreImpl value,
          $Res Function(_$SyncOutputDto_StoreImpl) then) =
      __$$SyncOutputDto_StoreImplCopyWithImpl<$Res>;
  @useResult
  $Res call({String convId, List<SyncMessageDto> messages});
}

/// @nodoc
class __$$SyncOutputDto_StoreImplCopyWithImpl<$Res>
    extends _$SyncOutputDtoCopyWithImpl<$Res, _$SyncOutputDto_StoreImpl>
    implements _$$SyncOutputDto_StoreImplCopyWith<$Res> {
  __$$SyncOutputDto_StoreImplCopyWithImpl(_$SyncOutputDto_StoreImpl _value,
      $Res Function(_$SyncOutputDto_StoreImpl) _then)
      : super(_value, _then);

  /// Create a copy of SyncOutputDto
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? convId = null,
    Object? messages = null,
  }) {
    return _then(_$SyncOutputDto_StoreImpl(
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

class _$SyncOutputDto_StoreImpl extends SyncOutputDto_Store {
  const _$SyncOutputDto_StoreImpl(
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
    return 'SyncOutputDto.store(convId: $convId, messages: $messages)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$SyncOutputDto_StoreImpl &&
            (identical(other.convId, convId) || other.convId == convId) &&
            const DeepCollectionEquality().equals(other._messages, _messages));
  }

  @override
  int get hashCode => Object.hash(
      runtimeType, convId, const DeepCollectionEquality().hash(_messages));

  /// Create a copy of SyncOutputDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$SyncOutputDto_StoreImplCopyWith<_$SyncOutputDto_StoreImpl> get copyWith =>
      __$$SyncOutputDto_StoreImplCopyWithImpl<_$SyncOutputDto_StoreImpl>(
          this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(Uint8List bytes) send,
    required TResult Function(String convId, List<SyncMessageDto> messages)
        store,
  }) {
    return store(convId, messages);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(Uint8List bytes)? send,
    TResult? Function(String convId, List<SyncMessageDto> messages)? store,
  }) {
    return store?.call(convId, messages);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(Uint8List bytes)? send,
    TResult Function(String convId, List<SyncMessageDto> messages)? store,
    required TResult orElse(),
  }) {
    if (store != null) {
      return store(convId, messages);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(SyncOutputDto_Send value) send,
    required TResult Function(SyncOutputDto_Store value) store,
  }) {
    return store(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(SyncOutputDto_Send value)? send,
    TResult? Function(SyncOutputDto_Store value)? store,
  }) {
    return store?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(SyncOutputDto_Send value)? send,
    TResult Function(SyncOutputDto_Store value)? store,
    required TResult orElse(),
  }) {
    if (store != null) {
      return store(this);
    }
    return orElse();
  }
}

abstract class SyncOutputDto_Store extends SyncOutputDto {
  const factory SyncOutputDto_Store(
          {required final String convId,
          required final List<SyncMessageDto> messages}) =
      _$SyncOutputDto_StoreImpl;
  const SyncOutputDto_Store._() : super._();

  String get convId;
  List<SyncMessageDto> get messages;

  /// Create a copy of SyncOutputDto
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$SyncOutputDto_StoreImplCopyWith<_$SyncOutputDto_StoreImpl> get copyWith =>
      throw _privateConstructorUsedError;
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
