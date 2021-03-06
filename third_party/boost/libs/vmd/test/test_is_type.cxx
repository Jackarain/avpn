
//  (C) Copyright Edward Diener 2011-2015
//  Use, modification and distribution are subject to the Boost Software License,
//  Version 1.0. (See accompanying file LICENSE_1_0.txt or copy at
//  http://www.boost.org/LICENSE_1_0.txt).

#include <boost/vmd/is_type.hpp>
#include <boost/detail/lightweight_test.hpp>
#include <boost/preprocessor/list/at.hpp>
#include <boost/preprocessor/seq/elem.hpp>
#include <boost/preprocessor/tuple/elem.hpp>

int main()
      {
  
#if BOOST_PP_VARIADICS

    #define A_TUPLE (*,#,BOOST_VMD_TYPE_ARRAY)
    #define JDATA BOOST_VMD_TYPE_LIST
    #define KDATA 222
    #define A_SEQ (BOOST_VMD_TYPE_TUPLE)(-)(#)
    #define A_LIST (BOOST_VMD_TYPE_SEQ,(BOOST_VMD_TYPE_EMPTY,(&,BOOST_PP_NIL)))
  
    BOOST_TEST(BOOST_VMD_IS_TYPE(BOOST_PP_TUPLE_ELEM(2,A_TUPLE)));
    BOOST_TEST(BOOST_VMD_IS_TYPE(JDATA));
    BOOST_TEST(BOOST_VMD_IS_TYPE(BOOST_PP_SEQ_ELEM(0,A_SEQ)));
    BOOST_TEST(BOOST_VMD_IS_TYPE(BOOST_PP_LIST_AT(A_LIST,0)));
    BOOST_TEST(BOOST_VMD_IS_TYPE(BOOST_PP_LIST_AT(A_LIST,1)));
    BOOST_TEST(!BOOST_VMD_IS_TYPE(KDATA));
    
#else

BOOST_ERROR("No variadic macro support");
  
#endif

      return boost::report_errors();
  
      }
