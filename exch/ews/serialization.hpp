// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022 grommunio GmbH
// This file is part of Gromox.

#pragma once

#include <cstdio>
#include <cmath>
#include <ctime>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include <gromox/clock.hpp>

#include <tinyxml2.h>

#include "exceptions.hpp"
#include "structures.hpp"

namespace gromox::EWS::Serialization
{
using SetterFunc = const std::function<void(const char*)>&;

///////////////////////////////////////////////////////////////////////////////////////////////////
//Conversion of built-in types

static constexpr uint8_t EC_IN = 1 << 0; ///< Needs explicit conversion on import
static constexpr uint8_t EC_OUT = 1 << 0; ///< Needs explicit conversion on export
static constexpr uint8_t EC_IMP_OUT = 1 << 2; ///< Can be exported implicitely by SetText

/**
 * @brief      Explicit conversion information
 *
 * Assumes by default that
 * - `T(const tinyxml2::XMLElement*)` can be used for imports
 * - `T().serialize(tinyxml2::XMLElement*)` can be used for exports
 *
 * This behavior should be implemented for every EWS structure, however
 * built-in data types and those provided by the standard library must be
 * converted explicitely by template specializations of this struct.
 *
 * A template specialization must contain
 * - `constexpr uint8t value` with a combination of `EC_IN` and `EC_OUT` or `EC_IMP_OUT`
 * - `tinyxml2::XMLError deserialize(const tinyxml2::XMLElement*, T&)` (`EC_IN` set)
 * - `tinyxml2::XMLError deserialize(const tinyxml2::XMLAttribute*, T&)` (`EC_IN` set)
 * - `void serialize(const T&, SetterFunc)` (`EC_OUT` set)
 *
 * SetterFunc is a function with signature `void(const char*)` that is to be
 * called with the serialized data string.
 *
 * @tparam     T     Type to convert
 */
template<typename T>
struct ExplicitConvert
{static const uint8_t value = 0;};

/**
 * @brief      Conversion specialization for boolean
 */
template<>
struct ExplicitConvert<bool>
{
	static constexpr uint8_t value = EC_IN | EC_IMP_OUT;

	static tinyxml2::XMLError deserialize(const tinyxml2::XMLElement* xml, bool& value)
	{return xml->QueryBoolText(&value);}

	static tinyxml2::XMLError deserialize(const tinyxml2::XMLAttribute* xml, bool& value)
	{return xml->QueryBoolValue(&value);}
};

/**
 * @brief      Conversion specialization for integer
 */
template<>
struct ExplicitConvert<int32_t>
{
	static constexpr uint8_t value = EC_IN | EC_IMP_OUT;

	static tinyxml2::XMLError deserialize(const tinyxml2::XMLElement* xml, int32_t& value)
	{return xml->QueryIntText(&value);}

	static tinyxml2::XMLError deserialize(const tinyxml2::XMLAttribute* xml, int32_t& value)
	{return xml->QueryIntValue(&value);}
};

/**
 * @brief      Conversion specialization for std::string
 */
template<>
struct ExplicitConvert<std::string>
{
	static constexpr uint8_t value = EC_IN | EC_OUT;

	static inline tinyxml2::XMLError deserialize(const tinyxml2::XMLElement* xml, std::string& value)
	{
		const char* data = xml->GetText();
		if(!data)
			return tinyxml2::XML_NO_TEXT_NODE;
		value = data;
		return tinyxml2::XML_SUCCESS;
	}

	static inline tinyxml2::XMLError deserialize(const tinyxml2::XMLAttribute* xml, std::string& value)
	{
		value = xml->Value();
		return tinyxml2::XML_SUCCESS;
	}

	static inline void serialize(const std::string& value, SetterFunc setter)
	{
		if(value.length())
			setter(value.c_str());
	}
};

/**
 * @brief      Conversion specialization for timestamps
 *
 * @todo       Implement deserialization
 */
template<>
struct ExplicitConvert<gromox::time_point>
{
	static constexpr uint8_t value = EC_IN | EC_OUT;

	static tinyxml2::XMLError deserialize(const tinyxml2::XMLElement*, gromox::time_point&);

	static inline void serialize(const gromox::time_point& value, SetterFunc setter)
	{
		tm t;
		char timestr[64];
		time_t timestamp = gromox::time_point::clock::to_time_t(value);
		gmtime_r(&timestamp, &t);
		auto frac = value.time_since_epoch() % std::chrono::seconds(1);
		long fsec = std::chrono::duration_cast<std::chrono::microseconds>(frac).count();
		snprintf(timestr, 64, fsec? "%04d-%02d-%02dT%02d:%02d:%02d.%06ldZ" : "%04d-%02d-%02dT%02d:%02d:%02dZ",
		         t.tm_year+1900, t.tm_mon+1, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec, fsec);
		setter(timestr);
	}
};

/**
 * @brief      Conversion specialization for StrEnum
 */
template<const char* C0, const char*... Cs>
struct ExplicitConvert<gromox::EWS::Structures::StrEnum<C0, Cs...>>
{
	using T = gromox::EWS::Structures::StrEnum<C0, Cs...>;

	static constexpr uint8_t value = EC_IN | EC_OUT;

	static inline tinyxml2::XMLError deserialize(const tinyxml2::XMLElement* xml, T& value)
	{
		const char* data = xml->GetText();
		if(!data)
			return tinyxml2::XML_NO_TEXT_NODE;
		try {
			value = data;
		} catch (gromox::EWS::Exceptions::EnumError& err) {
			throw gromox::EWS::Exceptions::DeserializationError(err.what());
		}
		return tinyxml2::XML_SUCCESS;
	}

	static inline tinyxml2::XMLError deserialize(const tinyxml2::XMLAttribute* xml, T& value)
	{
		value = xml->Value();
		return tinyxml2::XML_SUCCESS;
	}

	static inline void serialize(const T& value, SetterFunc setter)
	{
		if(value.length())
			setter(value.c_str());
	}
};

///////////////////////////////////////////////////////////////////////////////
//Type unpacking

enum Container {NONE, OPTIONAL, LIST}; ///< Container information

/**
 * @brief      Helper struct to unpack underlying types
 *
 * Helps to access the actual data type contained in std::optional
 * and std::vector, along with information about the container.
 *
 * @tparam     T     Container type
 */
template<typename T> struct BaseType {
	using type = T;
	static constexpr Container container = NONE;
};

/**
 * @brief      Container information for std::optional
 */
template<typename T> struct BaseType<std::optional<T>> {
	using type = T;
	static constexpr Container container = OPTIONAL;
};

/**
 * @brief      Container information for std::vector
 */
template<typename T> struct BaseType<std::vector<T>> {
	using type = T;
	static constexpr Container container = LIST;
};

template<typename T>
using BaseType_t = typename BaseType<T>::type;

///////////////////////////////////////////////////////////////////////////////
//Name retrieval

/**
 * @brief      Check if the type has a `NAME` member
 */
template<typename T>
struct HasName
{
	template<typename C> static uint8_t test(decltype(C::NAME));
	template<typename C> static uint16_t test(...);

	static constexpr bool value = sizeof(test<T>("")) == sizeof(uint8_t);
};

/**
 * @brief      Retrieve value of `NAME` member
 *
 * @param      def   Default value to return if type has no `NAME` member
 *
 * @tparam     T     Type to use the name member of
 *
 * @return     Name or default
 */
template<typename T>
static constexpr const char* getName(const char* def=nullptr)
{
	if constexpr(HasName<T>::value)
	    return T::NAME;
	else
	    return def;
}

///////////////////////////////////////////////////////////////////////////////
//Shortcuts

/**
 * @brief      Check whether explicit conversion bit is set
 *
 * @param      dir   Conversion direction flag
 *
 * @tparam     T     Type
 *
 * @return     true if bit is set, false otherwise
 */
template<typename T>
constexpr bool explicit_convert(uint8_t dir)
{return ExplicitConvert<BaseType_t<T>>::value & dir;}


///////////////////////////////////////////////////////////////////////////////
//Deserialization

template<typename T> static T fromXMLNodeDispatch(const tinyxml2::XMLElement*);

/**
 * @brief      Construct type from XMLElement
 *
 * Only applied if no explicit conversion is defined.
 *
 * @param      child      XMLElement containing data
 *
 * @tparam     T          Type to construct
 *
 * @return     Instance of the type
 */
template<typename T, std::enable_if_t<!explicit_convert<T>(EC_IN), bool> = true>
static T fromXMLNode(const tinyxml2::XMLElement* child)
{return T(child);}

/**
 * @brief      Deserialize type from XMLElement
 *
 * Only applied if explicit conversion is defined.
 *
 * @param      child      The child
 *
 * @tparam     T          Type to deserialize
 *
 * @return     Instance of the type
 */
template<typename T, std::enable_if_t<explicit_convert<T>(EC_IN), bool> = true>
static T fromXMLNode(const tinyxml2::XMLElement* child)
{
	using namespace std::string_literals;
	using gromox::EWS::Exceptions::DeserializationError;
	BaseType_t<T> val;
	tinyxml2::XMLError err = ExplicitConvert<BaseType_t<T>>::deserialize(child, val);
	if(err == tinyxml2::XML_NO_TEXT_NODE)
		throw DeserializationError("Element '"s+child->Name()+"'is empty");
	else if(err == tinyxml2::XML_CAN_NOT_CONVERT_TEXT)
		throw DeserializationError("Failed to convert element "s+child->Name()+"="+child->GetText()
	                               +"' to "+typeid(BaseType_t<T>).name());
	return val;
}

/**
 * @brief      Deserialize optional data node
 *
 * @param      child  XMLElement containing data or nullptr if not present
 *
 * @tparam     T      Any std::optional type
 *
 * @return     Data if present or empty optional otherwise
 */
template<typename T>
static T fromXMLNodeOpt(const tinyxml2::XMLElement* child)
{return child? T(fromXMLNodeDispatch<BaseType_t<T>>(child)) : std::nullopt;}

/**
 * @brief      Deserialize list of elements
 *
 * @param      child  XMLElement containing a list of elements
 *
 * @tparam     T      List type (i.e. std::vector)
 *
 * @return     List of values
 */
template<typename T>
static T fromXMLNodeList(const tinyxml2::XMLElement* child)
{
	T values;
	size_t count = 1;
	const char* name = getName<BaseType_t<T>>();
	for(const tinyxml2::XMLElement* entry = child->FirstChildElement(name); entry; entry=entry->NextSiblingElement(name))
		++count;
	values.reserve(count);
	for(const tinyxml2::XMLElement* entry = child->FirstChildElement(name); entry; entry=entry->NextSiblingElement(name))
		values.emplace_back(fromXMLNodeDispatch<BaseType_t<T>>(entry));
	return values;
}

/**
 * @brief      Unpack list type
 *
 * @param      child  XMLElement containing data
 *
 * @tparam     T      Type to unpack
 *
 * @return     Instance of type to construct
 */
template<typename T>
static T fromXMLNodeDispatch(const tinyxml2::XMLElement* child)
{
	if constexpr(BaseType<T>::container == LIST)
		return fromXMLNodeList<T>(child);
	else
		return fromXMLNode<T>(child);
}

/**
 * @brief      Deserialize type child element
 *
 * @param      xml   Parent XMLElement
 * @param      name  Name of the child element to construct from
 *
 * @tparam     T     Type to deserialize
 *
 * @throw      DeserializationError   Deserialization failed
 *
 * @return     New instance of the type
 */
template<typename T>
static T fromXMLNode(const tinyxml2::XMLElement* xml, const char* name)
{
	using namespace std::string_literals;
	using gromox::EWS::Exceptions::DeserializationError;
	const tinyxml2::XMLElement* child = xml->FirstChildElement(name);
	if constexpr(BaseType<T>::container == OPTIONAL)
	    return fromXMLNodeOpt<T>(child);
	else if(!child)
		throw DeserializationError("Missing required child element '"s+name+"' in element '"+xml->Name()+"'");
	else
		return fromXMLNodeDispatch<T>(child);
}

/**
 * @brief      Deserialize type from attribute
 *
 * Only defined if explicit conversion is defined as complex types
 * cannot be stored in attributes anyway.
 *
 * @param      xml        Parent XMLElement
 * @param      name       Name of the attribute to construct from
 *
 * @tparam     T          Type to deserialize
 *
 * @return     New instance of the type
 */
template<typename T, std::enable_if_t<explicit_convert<T>(EC_IN), bool> = true>
static T fromXMLAttr(const tinyxml2::XMLElement* xml, const char* name)
{
	static_assert(BaseType<T>::container != LIST, "Cannot read list from attribute");

	using namespace std::string_literals;
	using gromox::EWS::Exceptions::DeserializationError;
	const tinyxml2::XMLAttribute* attr = xml->FindAttribute(name);
	if(!attr)
	{
		if constexpr(BaseType<T>::container == OPTIONAL)
		    return std::nullopt;
		throw DeserializationError("Missing required attribute '"s+name+"' in element '"+xml->Name()+"'");
	}
	BaseType_t<T> val;
	tinyxml2::XMLError err = ExplicitConvert<BaseType_t<T>>::deserialize(attr, val);
	if(err == tinyxml2::XML_WRONG_ATTRIBUTE_TYPE)
		throw DeserializationError("Failed to convert attribute "s+name+"="+attr->Value()+" in element '"+xml->Name()
	                               +"' to "+typeid(BaseType_t<T>).name());
	return val;
}

///////////////////////////////////////////////////////////////////////////////
//Serialization

template<typename T> static void toXMLNodeDispatch(tinyxml2::XMLElement*, const T&);
template<typename T> static void toXMLNode(tinyxml2::XMLElement*, const char*, const T&);

/**
 * @brief      Fill XMLElement with serialized data
 *
 * @param      xml    XMLElement to store data in
 * @param      value  Value to store
 *
 * @tparam     T      Data type to store
 */
template<typename T>
static void toXMLNode(tinyxml2::XMLElement* xml, const T& value)
{
	if constexpr(explicit_convert<T>(EC_IMP_OUT))
		xml->SetText(value);
	else if constexpr(explicit_convert<T>(EC_OUT))
		ExplicitConvert<BaseType_t<T>>::serialize(value, [xml](const char* data){xml->SetText(data);});
	else
		value.serialize(xml);
}

/**
 * @brief      Unpack type stored in optional
 *
 * Helper function as direct recursion is not possible with template functions.
 */
template<typename T>
static void toXmlNodeOpt(tinyxml2::XMLElement* xml, const T& value)
{
	toXMLNodeDispatch<BaseType_t<T>>(xml, value.value());
}

/**
 * @brief      Serialize list of values
 *
 * @param      xml    XMLElement to store data in
 * @param      value  List to serialize
 *
 * @tparam     T      List type
 */
template<typename T>
static void toXMLNodeList(tinyxml2::XMLElement* xml, const T& value)
{
	using BT = BaseType_t<T>;
	const char* name = getName<BT>("x");
	for(const BT& element : value)
		toXMLNode<BT>(xml, name, element);
}

/**
 * @brief      Unpack encapsulating types (optional and list)
 *
 * @param      xml    XMLElement to store data in
 * @param      value  The value
 *
 * @tparam     T      Type to serialize
 */
template<typename T>
static void toXMLNodeDispatch(tinyxml2::XMLElement* xml, const T& value)
{
	if constexpr(BaseType<T>::container == OPTIONAL)
		toXmlNodeOpt<T>(xml, value);
	else if constexpr(BaseType<T>::container == LIST)
		toXMLNodeList<T>(xml, value);
	else
		toXMLNode(xml, value);
}

/**
 * @brief      Serialize data into XMLElement
 *
 * @param      parent  Parent XMLElement
 * @param      name    Name of the child node
 * @param      value   Value to store
 *
 * @tparam     T       Type to store
 */
template<typename T>
static void toXMLNode(tinyxml2::XMLElement* parent, const char* name, const T& value)
{
	if constexpr(BaseType<T>::container == OPTIONAL)
		if(!value)
		return;
	tinyxml2::XMLElement* xml = parent->InsertNewChildElement(name);
	toXMLNodeDispatch(xml, value);
}

/**
 * @brief      Serialize data into XMLAttribute
 *
 * @param      parent  Parent XMLElement
 * @param      name    Name of the attribute
 * @param      value   Value to store
 *
 * @tparam     T       Type to store
 */
template<typename T>
static void toXMLAttr(tinyxml2::XMLElement* parent, const char* name, const T& value)
{
	static_assert(BaseType<T>::container != LIST, "Cannot store list in attribute");
	const BaseType_t<T>* pvalue;
	if constexpr(BaseType<T>::container == OPTIONAL)
	{
		if(!value)
			return;
		pvalue = &value.value();
	}
	else
		pvalue = &value;
	if constexpr(explicit_convert<T>(EC_OUT))
		ExplicitConvert<BaseType_t<T>>::serialize(*pvalue, [parent, name](const char* data){parent->SetAttribute(name, data);});
	else
		parent->SetAttribute(name, value);
}

}
