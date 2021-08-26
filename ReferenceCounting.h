/*
 * Reference counting classes.
 * Written and tested with:
 * Borland C++ Builder 3.0, 5.0.
 * Microsoft C++.NET (7.00)
 *
 * References:
 * Bjarne Stroustrup, The C++ Programming Language Third Edition, 27.7.
 *
 * Author:
 * Boris Botstein.
 * boris.botstein@gmail.com
 *
 * Created: 18 Oct 1999.
 * Simplified: 16 Feb 2003.
 */

#ifndef REFCNT_HPP
#define REFCNT_HPP

#include <exception>
using namespace std;

template < class X > class value_ref {
protected:
	class holder {
	public:
		X* rep;
		unsigned count;

		holder(X* ptr) : rep(ptr), count(1) {}
		~holder() { delete rep; }
	};
	holder* value;

	void unbind() { if(--value->count == 0) delete value; }

	X* pointer() const {
		if(!value->rep) throw runtime_error("value_ref::pointer()");
		return value->rep;
	}
	X& reference() const {
		return *pointer();
	}

public:
	explicit value_ref(X* ptr = 0) : value(new holder(ptr)) {}
	value_ref(const value_ref< X >& rhs) : value(rhs.value) {
		value->count++;
	}
	~value_ref() { unbind(); }

	void bind(const value_ref< X >& rhs) {
		if(rhs.value != value) {
			unbind();
			value = rhs.value;
			value->count++;
		}
	}
	void bind(X* ptr) {
		if(value->rep != ptr) {
			unbind();
			value = new holder(ptr);
		}
	}

	value_ref< X >& operator=(const value_ref< X >& rhs) {
		bind(rhs);
		return *this;
	}
	value_ref< X >& operator=(X* ptr) {
		bind(ptr);
		return *this;
	}

	X* operator->() { return pointer(); }
	X& operator*() { return reference(); }

	const X* operator->() const { return pointer(); }
	const X& operator*() const { return reference(); }

	operator X&() const { return reference(); }
	operator X*() const { return pointer(); }

	operator const X&() const { return reference(); }
	operator const X*() const { return pointer(); }
};

template < class X > class key_ref : public value_ref< X > {
public:
	explicit key_ref(X* ptr = 0) : value_ref< X >(ptr) {}
	key_ref(const key_ref< X >& rhs) : value_ref< X >(rhs) {}

	key_ref< X >& operator=(const key_ref< X >& rhs) {
		value_ref< X >::operator=(rhs);
		return *this;
	}
	key_ref< X >& operator=(X* ptr) {
		value_ref< X >::operator=(ptr);
		return *this;
	}

	bool operator==(const key_ref< X >& rhs) const {
		return reference() == rhs.reference();
	}
	bool operator<(const key_ref< X >& rhs) const {
		return reference() < rhs.reference();
	}
};

#endif // REFCNT_HPP
